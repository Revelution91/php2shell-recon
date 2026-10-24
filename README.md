# php2shell-recon

![CI](https://github.com/Revelution91/php2shell-recon/actions/workflows/ci.yml/badge.svg)

Passive recon tool for identifying externally-visible PHP infrastructure
potentially exposed to **php2shell** ([CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)
/ [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)), a pair
of critical, actively-exploited PHP vulnerabilities disclosed 2026-10-21.

Built for third-party / vendor risk triage: point it at a list of vendor
domains, and it tells you which ones are likely running vulnerable PHP,
without sending exploit traffic or actively attacking anything by default.

## What it does

1. Enumerates subdomains for each target domain via [crt.sh](https://crt.sh)
   certificate transparency logs (passive, no interaction with the target).
2. Resolves every discovered host to an IP.
3. Checks each unique IP against Shodan's free, keyless
   [InternetDB](https://internetdb.shodan.io) endpoint for open ports and
   CPE/version banner data (passive, third-party cached data).
4. Classifies any detected PHP version against the php2shell patched-version
   table.
5. Reports results to the terminal and, optionally, to a file (text, JSON,
   or CSV).

Along the way it automatically: retries crt.sh/InternetDB requests with
backoff on rate limits (HTTP 429) and transient errors; detects wildcard DNS
per domain and filters out non-distinct subdomains that just share the
catch-all IP; skips private/internal IPs (never scanned by Shodan); and
flags hosts InternetDB tags as CDN/cloud infrastructure, since those results
are the most likely to describe an edge node rather than the real origin.

## Passive vs. active

By default, **nothing in this tool sends traffic directly to a scanned
target.** All data comes from crt.sh and Shodan InternetDB, both third-party
services that have already done the scanning independently of you running
this tool.

The one exception is the opt-in `--verify-headers` flag, which sends a single
HTTP `HEAD` request per flagged host directly to that host, to confirm or
refute InternetDB's data with a live header check. InternetDB's cached data
can be stale, or can reflect a CDN/load-balancer/edge node in front of the
real origin server rather than the origin itself — a single `HEAD` request is
the most reliable free way to cut through that.

**Only enable `--verify-headers` against infrastructure you own or have
explicit authorization to test.** A single `HEAD` request is a low-impact,
broadly-accepted form of reconnaissance (equivalent to visiting the page in a
browser), but it is still active interaction with someone else's
infrastructure, and the authorization question is yours to answer, not this
tool's. For third-party vendors you don't control, the recommended workflow
is: let the passive pass flag likely candidates, then follow up with the
vendor directly to confirm their patch status, rather than probing their
infrastructure yourself.

This tool does not implement any exploit code, does not send payloads
designed to trigger memory exhaustion or crash conditions, and is not a
substitute for an authorized penetration test.

## Installation

```bash
git clone https://github.com/<your-username>/php2shell-recon.git
cd php2shell-recon
pip install -r requirements.txt
```

Requires Python 3.8+.

## Usage

### Single domain

```bash
python3 php2shell_recon.py -d example.com
```

### List of domains (e.g. a vendor list)

```bash
python3 php2shell_recon.py -l vendor_domains.txt
```

`vendor_domains.txt` is one apex domain per line, no `http://`, no `www.`:

```
vendor1.com
vendor2.org
vendor3.io
```

### Skip subdomain enumeration (just check the given domain(s) directly)

```bash
python3 php2shell_recon.py -d example.com --no-subdomains
```

### Save output to a file

Modeled on nmap's `-oN` / `-oX` / `-oG` style:

```bash
# Normal text report
python3 php2shell_recon.py -l vendors.txt -oN report.txt

# JSON
python3 php2shell_recon.py -l vendors.txt -oJ report.json

# CSV
python3 php2shell_recon.py -l vendors.txt -oC report.csv

# All three at once
python3 php2shell_recon.py -l vendors.txt -oA report
# writes report.txt, report.json, report.csv
```

All output flags are optional — with none specified, results print to the
terminal only.

### Live header verification (opt-in, active — see note above)

```bash
python3 php2shell_recon.py -d yourowndomain.com --verify-headers
```

### Tuning concurrency / timeouts

```bash
python3 php2shell_recon.py -l vendors.txt -c 50 -t 15
```

- `-c / --concurrency` — max concurrent requests (default: 30)
- `-t / --timeout` — per-request timeout in seconds (default: 10)

### Full option list

```bash
python3 php2shell_recon.py --help
```

## Output fields

| Field | Meaning |
|---|---|
| `vendor_domain` | The apex domain you supplied |
| `subdomain` | The specific host checked |
| `ip` | Resolved IP address |
| `open_ports` | Ports InternetDB saw open |
| `cpes` | CPE strings InternetDB reported (software/version fingerprints) |
| `other_vulns` | Any CVEs Shodan has already correlated to this host (unrelated to php2shell unless it happens to be listed) |
| `php_version` | PHP version extracted from the CPE data, if present |
| `php2shell_status` | See table below |
| `likely_cdn` | `yes` if Shodan InternetDB tagged this IP as CDN/cloud infrastructure — a signal the data may describe an edge node, not the real origin |
| `live_server_header` / `live_x_powered_by` | Only populated with `--verify-headers` |

## `php2shell_status` values

| Status | Meaning |
|---|---|
| `VULNERABLE_UNPATCHED` | PHP version detected, below the patched version for its branch |
| `VULNERABLE_EOL` | PHP 8.1 or earlier — end-of-life, no patch exists or will exist |
| `PATCHED` | PHP version detected, at or above the patched version |
| `UNKNOWN_BRANCH` | A PHP version was detected on a branch not yet mapped in this tool (e.g. a future release) — verify manually |
| `NO_VERSION` | PHP appears present (via CPE data) but no parseable version string was found |
| `PRIVATE_IP` | Host resolved to an RFC1918/loopback/link-local address — not scanned by Shodan, not checked |

Patched versions per branch, per the official advisory:

| Branch | Patched version |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| ≤8.1 | No patch (EOL) |

## Known limitations

- **InternetDB data can be stale.** It reflects Shodan's last scan of that
  IP, which may predate a recent patch.
- **CDN/edge-fronted hosts give unreliable passive results.** If a target
  sits behind Cloudflare, Fastly, Varnish, an AWS load balancer, or a managed
  host like Acquia/Pantheon, InternetDB is often fingerprinting the edge
  layer, not the real origin server. The tool flags this automatically when
  Shodan's own data tags the IP as CDN/cloud infrastructure (`likely_cdn:
  yes`), but the absence of that tag isn't a guarantee either — treat any
  `VULNERABLE_*` or `PATCHED` result on a CDN-flagged or otherwise unclear
  host as unconfirmed until checked another way (e.g. `--verify-headers`, or
  asking the vendor directly).
- **A blank/`NO_VERSION` result does not mean a host is safe** — many
  production servers deliberately strip version headers. Treat gaps as
  unknown, not clear.
- **This tool only checks IPv4 `A` records.** IPv6-only hosts are not
  currently resolved.
- **Wildcard DNS is detected and filtered**, but only at the "does a random
  nonexistent subdomain resolve" level. A domain with partial/conditional
  wildcarding could still slip through.
- **`other_vulns` is independent of `php2shell_status`.** Since these CVEs
  were disclosed very recently, Shodan's own CVE correlation for them will
  likely lag; `php2shell_status` is computed directly from the detected PHP
  version specifically so it isn't blocked on that lag. The `other_vulns`
  field is just whatever else Shodan has already tagged for that host, shown
  for reference.
- **Private/internal IPs are skipped** (not queried against InternetDB,
  since Shodan never scans non-public address space) and reported with
  status `PRIVATE_IP` instead.

## Disclaimer

This tool is provided for authorized security research, vendor risk
assessment, and defensive purposes only. Running the default (passive) mode
against third-party domains does not send traffic to them, but you are
responsible for complying with your organization's policies and any
applicable law when using this tool, especially if you enable
`--verify-headers`. The authors assume no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome. A few areas that could use work:

- IPv6 (`AAAA`) resolution
- Censys as a secondary passive data source alongside InternetDB
- A `--diff` mode to compare two runs over time
