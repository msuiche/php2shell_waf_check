# php2shell WAF check

Non-destructive validator for edge protection against
**CVE-2026-109618 / CVE-2026-109619 ("php2shell")** — the critical PHP
`session.upload_progress` memory-safety flaws disclosed 2026-10-21
(CVSS 9.2, all PHP ≥ 5.4, fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).

It answers one question per target:

> **Is the edge (e.g. Cloudflare WAF) blocking requests shaped like a
> php2shell exploit?**

It does **not** exploit anything, and it does **not** tell you the origin
PHP version. It validates the compensating control only. Patch status must
still be verified server-side.

Two implementations, same logic:

| Script | Requirements | Output |
|---|---|---|
| `check_php2shell_waf.py` | Python 3 + system `curl` | colored, per-host detail, summary |
| `check-php2shell-waf.sh` | bash + curl | plain one-line-per-host |

## What it does

For each target URL it sends two tiny (~8 KB) `multipart/form-data` POSTs:

1. **control** — one benign form field. Expected to pass the edge and be
   answered by the origin (404/200/301 are all fine — we only care that it
   got through).
2. **shaped** — the exploit *shape*: a `PHP_SESSION_UPLOAD_PROGRESS` field,
   `t[]` array fields, and two small file parts (the CVE-2026-109619
   two-file layout). Far below any size threshold; PHP parses this in
   microseconds and no worker is harmed.

**Verdict logic**

| control | shaped | verdict |
|---|---|---|
| passes | 403 + Cloudflare block page | **PROTECTED** — edge rule fires on the exploit shape |
| passes | passes | **NOT BLOCKED** — exploit shape reaches the origin |
| 403 too | 403 | **INCONCLUSIVE** — something blocks all multipart POSTs |
| redirect | — | **REDIRECT** — re-run against the redirect target |

Exit code is `0` only when every target is PROTECTED, so it drops straight
into CI or a cron monitor.

## Usage

```bash
# Python (colored)
python3 check_php2shell_waf.py [options] [url ...]

# Bash
./check-php2shell-waf.sh [url ...]
```

Three ways to supply targets:

```bash
# 1. ad-hoc URLs on the command line
python3 check_php2shell_waf.py https://acme.com/upload.php https://acme.com/contact

# 2. explicit targets file
python3 check_php2shell_waf.py --targets-file my-engagement.txt

# 3. default: targets.txt next to the script, or ./targets.txt
cp targets.example.txt targets.txt   # then edit
python3 check_php2shell_waf.py
```

Flags (Python): `--targets-file FILE`, `--no-color`, `-h`.

## Targets file format

One URL per line. Blank lines and `#` comments are ignored.

```
# Acme Corp — php2shell edge validation, 2026-10
https://acme.com/wp-json/
https://www.acme.com/blog/wp-json/   # www proxies /blog/ to the PHP origin
```

`targets.txt` is gitignored — real engagement lists stay local.

Pick URLs that actually execute PHP behind the edge. Good candidates:
`/wp-json/` on WordPress, any form endpoint, or the site's front controller.
Avoid URLs that 301 at the edge (the checker will tell you to re-target).

## Reading the results

- **PROTECTED everywhere** → the managed WAF rules for php2shell are
  deployed and blocking on that zone. Still verify origin PHP versions —
  WAF rules lag payload mutations and are defense-in-depth, not a fix.
- **NOT BLOCKED** → the exploit shape reached PHP. Escalate: enable/verify
  your WAF ruleset (block mode) and check the PHP version immediately.
- **INCONCLUSIVE** → usually a blanket POST block or bot rule. Validate
  with a browser-shaped session or from an allowlisted IP.

## Safety

The shaped payload is ~8 KB with 4 KB file parts — orders of magnitude
below anything that stresses the parser. No memory pressure, no grooming
volume, no crash. It exercises the WAF's pattern match, not the bug. Only
run it against infrastructure you are authorized to test.

## Author

Matt Suiche, Tolmo ([@msuiche](https://github.com/msuiche))
