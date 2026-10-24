#!/usr/bin/env python3
"""
php2shell-recon
================

Passive recon tool for identifying externally-visible PHP infrastructure
potentially exposed to php2shell (CVE-2026-109618 / CVE-2026-109619).

Data sources used (all passive, third-party, no packets sent to targets
by default):
  - crt.sh              certificate transparency log search (subdomain enum)
  - internetdb.shodan.io free, keyless Shodan InternetDB endpoint (banner/CPE data)

An opt-in --verify-headers flag will send a single HTTP HEAD request per
flagged host directly to that host, to confirm/refute InternetDB's
(sometimes stale or CDN-fronted) data against live headers. This is OFF
by default -- see README.md "Passive vs. active" section before enabling
it against infrastructure you do not own or have authorization to test.

License: MIT. See LICENSE.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import re
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import requests

__version__ = "1.0.0"

CRTSH_URL = "https://crt.sh/"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

# php2shell (CVE-2026-109618 / CVE-2026-109619) patched versions, per branch.
# PHP 8.1 and earlier are EOL -- no patch exists or ever will for those.
PATCHED_VERSIONS = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}

CPE_PHP_RE = re.compile(r"cpe:/a:php:php:(\d+)\.(\d+)\.(\d+)")

STATUS_VULNERABLE_EOL = "VULNERABLE_EOL"
STATUS_VULNERABLE_UNPATCHED = "VULNERABLE_UNPATCHED"
STATUS_PATCHED = "PATCHED"
STATUS_UNKNOWN_BRANCH = "UNKNOWN_BRANCH"
STATUS_NO_VERSION = "NO_VERSION"
STATUS_NO_DATA = "NO_DATA"

RISK_STATUSES = {STATUS_VULNERABLE_EOL, STATUS_VULNERABLE_UNPATCHED}

# ANSI colors (disabled automatically with --no-color or when not a TTY)
class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{color}{text}{C.RESET}"


@dataclass
class HostResult:
    vendor_domain: str
    subdomain: str
    ip: Optional[str] = None
    open_ports: list = field(default_factory=list)
    cpes: list = field(default_factory=list)
    other_vulns: list = field(default_factory=list)
    php_version: Optional[str] = None
    status: str = STATUS_NO_DATA
    live_server_header: Optional[str] = None
    live_powered_by_header: Optional[str] = None

    def to_row(self) -> dict:
        return {
            "vendor_domain": self.vendor_domain,
            "subdomain": self.subdomain,
            "ip": self.ip or "",
            "open_ports": ";".join(str(p) for p in self.open_ports),
            "cpes": ";".join(self.cpes),
            "other_vulns": ";".join(self.other_vulns),
            "php_version": self.php_version or "",
            "php2shell_status": self.status,
            "live_server_header": self.live_server_header or "",
            "live_x_powered_by": self.live_powered_by_header or "",
        }


def classify_php2shell(version: Optional[str]) -> str:
    """Classify a dotted PHP version string against php2shell patch status."""
    if not version:
        return STATUS_NO_VERSION

    try:
        major, minor, patch = (int(x) for x in version.split(".")[:3])
    except (ValueError, IndexError):
        return STATUS_NO_VERSION

    if major < 8 or (major == 8 and minor <= 1):
        return STATUS_VULNERABLE_EOL

    patched = PATCHED_VERSIONS.get((major, minor))
    if patched is None:
        return STATUS_UNKNOWN_BRANCH

    if (major, minor, patch) < patched:
        return STATUS_VULNERABLE_UNPATCHED
    return STATUS_PATCHED


def extract_php_version(cpes: list) -> Optional[str]:
    for cpe in cpes:
        m = CPE_PHP_RE.search(cpe)
        if m:
            return ".".join(m.groups())
    return None


def get_subdomains(domain: str, session: requests.Session, timeout: int) -> set:
    """Enumerate subdomains for a domain via crt.sh certificate transparency logs."""
    try:
        resp = session.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout,
        )
        resp.raise_for_status()
        entries = resp.json()
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return {domain}

    names = set()
    for entry in entries:
        for name in str(entry.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name:
                names.add(name)
    names.add(domain)
    return names


def resolve_host(hostname: str, timeout: int) -> Optional[str]:
    """Resolve a hostname to its first IPv4 A record, or None."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout, UnicodeError, OSError):
        return None


def query_internetdb(ip: str, session: requests.Session, timeout: int) -> Optional[dict]:
    """Query Shodan's free InternetDB for a single IP. Returns None on miss/error."""
    try:
        resp = session.get(INTERNETDB_URL.format(ip=ip), timeout=timeout)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if "detail" in data:
            return None
        return data
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return None


def verify_live_headers(hostname: str, session: requests.Session, timeout: int) -> tuple:
    """
    Opt-in ONLY (--verify-headers). Sends a single HTTP HEAD request directly
    to the host to read Server / X-Powered-By headers live, since InternetDB
    data can be stale or reflect a CDN/edge layer rather than the real origin.
    """
    for scheme in ("https", "http"):
        try:
            resp = session.head(
                f"{scheme}://{hostname}",
                timeout=timeout,
                allow_redirects=True,
            )
            server = resp.headers.get("Server")
            powered_by = resp.headers.get("X-Powered-By")
            if server or powered_by:
                return server, powered_by
        except requests.RequestException:
            continue
    return None, None


def build_host_list(domains: list, no_subdomains: bool, session: requests.Session,
                     timeout: int, concurrency: int, quiet: bool) -> list:
    """Returns a list of (vendor_domain, subdomain) pairs."""
    pairs = []

    if no_subdomains:
        for d in domains:
            pairs.append((d, d))
        return pairs

    if not quiet:
        print(f"{C.DIM}[*] Enumerating subdomains via crt.sh...{C.RESET}", file=sys.stderr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(concurrency, len(domains) or 1)) as ex:
        futures = {ex.submit(get_subdomains, d, session, timeout): d for d in domains}
        for fut in concurrent.futures.as_completed(futures):
            vendor = futures[fut]
            try:
                subs = fut.result()
            except Exception:
                subs = {vendor}
            if not quiet:
                print(f"{C.DIM}    {vendor}: {len(subs)} hosts{C.RESET}", file=sys.stderr)
            for s in subs:
                pairs.append((vendor, s))

    return pairs


def run_recon(domains: list, no_subdomains: bool, concurrency: int, timeout: int,
              verify_headers: bool, quiet: bool, use_color: bool) -> list:
    session = requests.Session()
    session.headers.update({"User-Agent": f"php2shell-recon/{__version__}"})

    pairs = build_host_list(domains, no_subdomains, session, timeout, concurrency, quiet)
    unique_hosts = sorted({sub for _vendor, sub in pairs})

    if not quiet:
        print(
            f"{C.DIM}[*] Resolving {len(unique_hosts)} unique hosts "
            f"(concurrency={concurrency})...{C.RESET}",
            file=sys.stderr,
        )

    host_ip: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(resolve_host, h, timeout): h for h in unique_hosts}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            try:
                host_ip[host] = fut.result()
            except Exception:
                host_ip[host] = None

    unique_ips = sorted({ip for ip in host_ip.values() if ip})

    if not quiet:
        print(
            f"{C.DIM}[*] Querying InternetDB for {len(unique_ips)} unique IPs "
            f"(concurrency={concurrency})...{C.RESET}",
            file=sys.stderr,
        )

    ip_data: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(query_internetdb, ip, session, timeout): ip for ip in unique_ips}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                ip_data[ip] = fut.result()
            except Exception:
                ip_data[ip] = None

    results: list = []
    for vendor, sub in pairs:
        ip = host_ip.get(sub)
        r = HostResult(vendor_domain=vendor, subdomain=sub, ip=ip)

        data = ip_data.get(ip) if ip else None
        if data:
            r.open_ports = data.get("ports", []) or []
            r.cpes = data.get("cpes", []) or []
            r.other_vulns = data.get("vulns", []) or []
            php_cpes = [c for c in r.cpes if "php" in c.lower()]
            if php_cpes:
                r.php_version = extract_php_version(php_cpes)
                r.status = classify_php2shell(r.php_version)

        results.append(r)

    # Only hosts InternetDB actually had port data for are "real" results;
    # drop pure dead-air entries (no IP or no InternetDB record at all) from
    # the interesting set, but keep them available if the caller wants them.
    interesting = [r for r in results if r.ip and r.open_ports]

    if verify_headers:
        risky = [r for r in interesting if r.status in RISK_STATUSES or r.status in (STATUS_UNKNOWN_BRANCH, STATUS_NO_VERSION)]
        if risky and not quiet:
            print(
                f"{C.YELLOW}[*] --verify-headers: sending a live HEAD request to "
                f"{len(risky)} flagged/unclear host(s) to confirm against InternetDB "
                f"data (CDN/edge fronting can make InternetDB stale or wrong).{C.RESET}",
                file=sys.stderr,
            )
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {ex.submit(verify_live_headers, r.subdomain, session, timeout): r for r in risky}
            for fut in concurrent.futures.as_completed(futures):
                r = futures[fut]
                try:
                    server, powered_by = fut.result()
                    r.live_server_header = server
                    r.live_powered_by_header = powered_by
                except Exception:
                    pass

    return interesting


# ---------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------

def status_marker(status: str, use_color: bool) -> str:
    markers = {
        STATUS_VULNERABLE_EOL: ("[!!]", C.RED),
        STATUS_VULNERABLE_UNPATCHED: ("[!!]", C.RED),
        STATUS_UNKNOWN_BRANCH: ("[? ]", C.YELLOW),
        STATUS_NO_VERSION: ("[  ]", C.DIM),
        STATUS_PATCHED: ("[ok]", C.GREEN),
        STATUS_NO_DATA: ("[  ]", C.DIM),
    }
    text, color = markers.get(status, ("[  ]", C.DIM))
    return colorize(text, color, use_color)


def print_terminal_report(results: list, use_color: bool, quiet: bool) -> None:
    php_hosts = [r for r in results if r.php_version or r.status not in (STATUS_NO_DATA,)]
    php_hosts = [r for r in results if r.cpes and any("php" in c.lower() for c in r.cpes)]

    if not quiet:
        print()
        print(colorize("=" * 70, C.CYAN, use_color))
        print(colorize("  php2shell-recon results (CVE-2026-109618 / CVE-2026-109619)", C.BOLD, use_color))
        print(colorize("=" * 70, C.CYAN, use_color))
        print()

    for r in php_hosts:
        marker = status_marker(r.status, use_color)
        version_str = f"PHP {r.php_version}" if r.php_version else "PHP ?"
        line = f"  {marker} {r.subdomain:<40} {r.ip or '':<16} {version_str:<14} {r.status}"
        print(line)
        if r.live_server_header or r.live_powered_by_header:
            live_bits = []
            if r.live_server_header:
                live_bits.append(f"Server: {r.live_server_header}")
            if r.live_powered_by_header:
                live_bits.append(f"X-Powered-By: {r.live_powered_by_header}")
            print(colorize(f"         live check -> {', '.join(live_bits)}", C.CYAN, use_color))

    if quiet:
        return

    eol = sum(1 for r in results if r.status == STATUS_VULNERABLE_EOL)
    unpatched = sum(1 for r in results if r.status == STATUS_VULNERABLE_UNPATCHED)
    unknown = sum(1 for r in results if r.status == STATUS_UNKNOWN_BRANCH)
    no_version = sum(1 for r in results if r.status == STATUS_NO_VERSION and any("php" in c.lower() for c in r.cpes))

    print()
    print(colorize("-" * 70, C.CYAN, use_color))
    print(f"  Vulnerable (patch available, not applied): {colorize(str(unpatched), C.RED, use_color)}")
    print(f"  Vulnerable (EOL branch, no patch exists):   {colorize(str(eol), C.RED, use_color)}")
    print(f"  PHP detected, branch unmapped:              {colorize(str(unknown), C.YELLOW, use_color)}")
    print(f"  PHP detected, version unavailable:          {no_version}")
    print(colorize("-" * 70, C.CYAN, use_color))
    print()
    print(colorize(
        "NOTE: CVE-2026-109618 / -109619 were disclosed 2026-10-21. Shodan's own\n"
        "'vulns' CVE correlation will likely lag for these -- php2shell_status here\n"
        "is derived directly from the detected PHP version string, independent of\n"
        "that correlation delay.\n"
        "\n"
        "A result can be stale or wrong for hosts behind a CDN/edge layer\n"
        "(Cloudflare, Fastly, Varnish, managed hosts like Acquia/Pantheon) --\n"
        "InternetDB may be fingerprinting the edge node, not the origin. Re-run\n"
        "with --verify-headers for a live header check on flagged hosts, or\n"
        "confirm directly with the vendor before escalating a finding.",
        C.DIM, use_color,
    ))
    print()


def write_txt(results: list, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"php2shell-recon report -- generated {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"CVE-2026-109618 / CVE-2026-109619\n")
        f.write("=" * 70 + "\n\n")
        for r in results:
            if not (r.cpes and any("php" in c.lower() for c in r.cpes)):
                continue
            f.write(f"{r.vendor_domain} | {r.subdomain} | {r.ip} | "
                     f"PHP {r.php_version or '?'} | {r.status}\n")
            if r.live_server_header or r.live_powered_by_header:
                f.write(f"    live: Server={r.live_server_header or '-'} "
                         f"X-Powered-By={r.live_powered_by_header or '-'}\n")


def write_csv(results: list, path: str) -> None:
    fieldnames = [
        "vendor_domain", "subdomain", "ip", "open_ports", "cpes",
        "other_vulns", "php_version", "php2shell_status",
        "live_server_header", "live_x_powered_by",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r.to_row())


def write_json(results: list, path: str) -> None:
    payload = {
        "tool": "php2shell-recon",
        "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(),
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "results": [asdict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

DISCLAIMER = """\
php2shell-recon uses passive, third-party data sources (crt.sh, Shodan
InternetDB) by default and sends no packets to scanned targets. With
--verify-headers, it sends a single HTTP HEAD request directly to any
flagged host to confirm live header data. Only use that flag against
infrastructure you own or are explicitly authorized to test. See
README.md for details.
"""


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="php2shell-recon",
        description="Passive recon for php2shell (CVE-2026-109618 / CVE-2026-109619) exposure.",
        epilog=DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target_group = p.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-d", "--domain", metavar="DOMAIN",
        help="A single domain to check (e.g. example.com).",
    )
    target_group.add_argument(
        "-l", "--list", metavar="FILE",
        help="File with one apex domain per line.",
    )

    p.add_argument(
        "--no-subdomains", action="store_true",
        help="Skip crt.sh subdomain enumeration; check only the given domain(s) directly.",
    )
    p.add_argument(
        "-c", "--concurrency", type=int, default=30,
        help="Max concurrent requests/lookups (default: 30).",
    )
    p.add_argument(
        "-t", "--timeout", type=int, default=10,
        help="Per-request timeout in seconds (default: 10).",
    )
    p.add_argument(
        "--verify-headers", action="store_true",
        help="Opt-in: send one live HTTP HEAD request per flagged/unclear host to "
             "confirm InternetDB data. ACTIVE -- only use on authorized targets.",
    )

    out_group = p.add_argument_group("output")
    out_group.add_argument("-oN", metavar="FILE", dest="out_txt", help="Write a normal text report to FILE.")
    out_group.add_argument("-oJ", metavar="FILE", dest="out_json", help="Write a JSON report to FILE.")
    out_group.add_argument("-oC", metavar="FILE", dest="out_csv", help="Write a CSV report to FILE.")
    out_group.add_argument(
        "-oA", metavar="BASENAME", dest="out_all",
        help="Write all three formats at once: BASENAME.txt, BASENAME.json, BASENAME.csv",
    )

    p.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress progress/status messages and the summary block.")
    p.add_argument("--version", action="version", version=f"php2shell-recon {__version__}")

    return p


def load_domains(args: argparse.Namespace) -> list:
    if args.domain:
        return [args.domain.strip().lower()]

    domains = []
    try:
        with open(args.list, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.append(line)
    except OSError as e:
        print(f"Error reading {args.list}: {e}", file=sys.stderr)
        sys.exit(1)

    if not domains:
        print(f"No domains found in {args.list}", file=sys.stderr)
        sys.exit(1)

    return domains


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    use_color = sys.stdout.isatty() and not args.no_color
    domains = load_domains(args)

    if not args.quiet:
        print(colorize(DISCLAIMER, C.DIM, use_color), file=sys.stderr)

    start = time.time()
    results = run_recon(
        domains=domains,
        no_subdomains=args.no_subdomains,
        concurrency=max(1, args.concurrency),
        timeout=args.timeout,
        verify_headers=args.verify_headers,
        quiet=args.quiet,
        use_color=use_color,
    )
    elapsed = time.time() - start

    print_terminal_report(results, use_color, args.quiet)

    if not args.quiet:
        print(colorize(f"Completed in {elapsed:.1f}s.", C.DIM, use_color), file=sys.stderr)

    wrote_any = False
    if args.out_txt:
        write_txt(results, args.out_txt)
        wrote_any = True
    if args.out_json:
        write_json(results, args.out_json)
        wrote_any = True
    if args.out_csv:
        write_csv(results, args.out_csv)
        wrote_any = True
    if args.out_all:
        write_txt(results, f"{args.out_all}.txt")
        write_json(results, f"{args.out_all}.json")
        write_csv(results, f"{args.out_all}.csv")
        wrote_any = True

    if wrote_any and not args.quiet:
        print(colorize("Report(s) written.", C.GREEN, use_color), file=sys.stderr)


if __name__ == "__main__":
    main()
