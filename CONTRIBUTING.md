# Contributing to php2shell-recon

Thanks for taking a look at this. PRs and issues are welcome.

## Setup

```bash
git clone https://github.com/<your-username>/php2shell-recon.git
cd php2shell-recon
pip install -r requirements.txt -r requirements-dev.txt
```

## Running tests

```bash
pytest tests/ -v
```

Tests cover pure logic (version classification, CPE parsing, retry/backoff
behavior with a mocked session, private-IP detection) and don't hit the
real network — no live crt.sh/InternetDB calls happen in CI.

If you add a new function with any non-trivial branching (especially
anything touching the `php2shell_status` classification), please add a
test for it. A wrong classification here could mean someone trusts a
"PATCHED" result on a host that isn't — that's the one thing this tool
really can't get wrong silently.

## Linting

```bash
flake8 . --max-line-length=120
```

CI runs this too; syntax errors / undefined names will fail the build,
style warnings won't block a PR but are nice to clean up.

## Before opening a PR

- Run the test suite and make sure it's green
- If you changed CLI behavior, update `README.md` to match
- Keep the default (no-flag) behavior passive — see
  [README.md "Passive vs. active"](README.md#passive-vs-active). Any new
  feature that sends traffic directly to a scanned target should be
  opt-in, clearly named, and documented as active in both the `--help`
  text and the README.

## Ideas if you want somewhere to start

- IPv6 (`AAAA`) resolution — currently IPv4-only
- Censys as a secondary passive data source alongside InternetDB
- A `--diff` mode to compare two runs over time
- Local caching between runs (SQLite or JSON, keyed by IP/domain with a TTL)
- A Markdown output format (`-oM`) for pasting findings into tickets/chat
- ASN-based CDN detection as a fallback for IPs InternetDB hasn't tagged
  (current detection relies on InternetDB's own `tags` field, which won't
  catch every CDN/cloud IP)

## Code style

Nothing fancy — standard PEP 8, type hints on function signatures where
practical, docstrings on anything non-obvious. Match the existing style
in `php2shell_recon.py` rather than introducing a new convention.
