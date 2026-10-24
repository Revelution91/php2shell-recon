# Security Policy

This document is about the security of **this tool's own code**, not about
php2shell (CVE-2026-109618 / CVE-2026-109619) itself. For information on
those CVEs, see the official PHP security advisory and your distro's
patch notes.

## Reporting a vulnerability in php2shell-recon

If you find a security issue in this tool itself (e.g. a bug that could
cause it to leak credentials, execute unintended commands, or behave
unsafely), please report it privately rather than opening a public issue:

- Open a [GitHub Security Advisory](../../security/advisories/new) on this
  repo (preferred), or
- Open a regular issue without exploit details and ask for a private
  channel to share them

Please include:
- A description of the issue and its potential impact
- Steps to reproduce
- The version/commit you tested against

## Scope

In scope:
- Bugs in `php2shell_recon.py` that could cause unintended network
  behavior, credential exposure, or incorrect results that could lead
  someone to a false sense of security (e.g. silently misreporting a
  vulnerable host as patched)

Out of scope:
- Vulnerabilities in crt.sh, Shodan InternetDB, or other third-party
  services this tool queries — report those to the respective service
- The underlying php2shell CVEs themselves — report those through PHP's
  official security process, not here

## A note on responsible use

This tool is intended for authorized security research and vendor risk
assessment. See the [README's "Passive vs. active"](README.md#passive-vs-active)
section for guidance on what's appropriate to run against infrastructure
you don't own.
