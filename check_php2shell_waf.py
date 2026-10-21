#!/usr/bin/env python3
# Author: Matt Suiche, Tolmo (@msuiche)
"""
check_php2shell_waf.py — non-destructive WAF/mitigation validator for
CVE-2026-109618 / CVE-2026-109619 ("php2shell").

For each target URL it sends TWO tiny multipart/form-data POSTs:

  control  — a benign one-field form (~10 bytes). Expected to pass the edge
             and be answered by the origin (404/200/302 are all fine).
  shaped   — the php2shell exploit *shape* at harmless size (~8 KB):
             a PHP_SESSION_UPLOAD_PROGRESS field, array fields, and two
             file parts (the CVE-2026-109619 two-file layout). No oversized
             allocations, no grooming volume — PHP parses this in µs.

Verdict per target:
  control passes + shaped 403 w/ Cloudflare block page -> PROTECTED
  control passes + shaped passes                       -> NOT BLOCKED
  control also blocked                                 -> INCONCLUSIVE
  control redirects                                    -> retest hint

This validates the COMPENSATING CONTROL (edge WAF) only. It does not tell
you the origin PHP version and does not prove exploitability — patch status
still has to be verified server-side (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).

Usage:
  check_php2shell_waf.py https://example.com/upload.php [url ...]
  check_php2shell_waf.py --targets-file my-targets.txt
  check_php2shell_waf.py            # reads targets.txt next to the script or in the cwd
  check_php2shell_waf.py --no-color ...

Exit code: 0 if every target is PROTECTED, 1 otherwise.
"""

import argparse
import os
import subprocess
import sys
import tempfile

CF_BLOCK_MARKER = "attention required! | cloudflare"

PATCHED = "8.5.12 / 8.4.27 / 8.3.36 / 8.2.35"


def load_targets(path: str):
    """Read targets file: one URL per line, '#' comments and blanks ignored."""
    targets = []
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def default_targets_file():
    """targets.txt next to the script, else targets.txt in the cwd, else None."""
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, "targets.txt"), os.path.join(os.getcwd(), "targets.txt")):
        if os.path.isfile(cand):
            return cand
    return None


class C:
    """ANSI colors, disabled on request or when piped."""

    def __init__(self, enabled: bool):
        def mk(code):
            return (lambda s: f"\033[{code}m{s}\033[0m") if enabled else (lambda s: s)

        self.red = mk("31")
        self.green = mk("32")
        self.yellow = mk("33")
        self.blue = mk("34")
        self.magenta = mk("35")
        self.cyan = mk("36")
        self.bold = mk("1")
        self.dim = mk("2")


c = C(enabled=True)


def banner():
    print(c.bold(c.cyan("╔══════════════════════════════════════════════════════════╗")))
    print(c.bold(c.cyan("║") + c.bold("   php2shell WAF control check  ·  CVE-2026-109618/619     ") + c.bold(c.cyan("║"))))
    print(c.bold(c.cyan("╚══════════════════════════════════════════════════════════╝")))
    print(c.dim("  payloads are ~8 KB and harmless — this validates edge"))
    print(c.dim("  rules, NOT the origin patch level.\n"))


def post_multipart(url: str, shaped: bool):
    """One tiny multipart POST via curl. Returns (status_code, body_text, headers) or None on network error.

    Uses the system curl instead of urllib on purpose: macOS ships an old
    Python/OpenSSL that fails TLS 1.3-only edges, and curl's UA/TLS behavior
    also matches what got past bot detection during manual probing.
    """
    ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          "AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/130.0.0.0 Safari/537.36")

    with tempfile.TemporaryDirectory() as td:
        hdr_file = os.path.join(td, "h")
        body_file = os.path.join(td, "b")
        cmd = [
            "curl", "-sS", "-m", "20",
            "-A", ua,
            "-o", body_file, "-D", hdr_file,
            "-w", "%{http_code}", "-X", "POST",
        ]
        if shaped:
            f1 = os.path.join(td, "f1.bin")
            f2 = os.path.join(td, "f2.bin")
            with open(f1, "wb") as fh:
                fh.write(b"\x41" * 4096)
            with open(f2, "wb") as fh:
                fh.write(b"\x42" * 4096)
            cmd += ["-H", "Cookie: PHPSESSID=wafprobe0001",
                    "-F", "PHP_SESSION_UPLOAD_PROGRESS=probe",
                    "-F", "t[]=" + "A" * 32,
                    "-F", "t[]=" + "B" * 32,
                    "-F", "t[]=" + "C" * 32,
                    "-F", f"file1=@{f1};filename=first.bin;type=application/octet-stream",
                    "-F", f"file2=@{f2};filename=second.bin;type=application/octet-stream"]
        else:
            cmd += ["-F", "wafprobe=benign"]
        cmd.append(url)

        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=30)
        except (subprocess.SubprocessError, OSError):
            return None

        try:
            code = int(proc.stdout.decode().strip())
        except ValueError:
            return None
        if proc.returncode != 0 and code == 0:
            return None

        try:
            with open(body_file, "r", errors="replace") as fh:
                body = fh.read()
        except OSError:
            body = ""
        headers = {}
        try:
            with open(hdr_file, "r", errors="replace") as fh:
                for line in fh:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
        except OSError:
            pass
        return code, body, headers


def verdict_badge(kind: str) -> str:
    return {
        "protected": c.bold(c.green("● PROTECTED")),
        "open": c.bold(c.red("● NOT BLOCKED")),
        "inconclusive": c.bold(c.yellow("● INCONCLUSIVE")),
        "redirect": c.bold(c.blue("● REDIRECT")),
        "error": c.bold(c.magenta("● ERROR")),
    }[kind]


def probe(url: str) -> bool:
    print(c.bold(f"\n▶ {url}"))

    ctl = post_multipart(url, shaped=False)
    shp = post_multipart(url, shaped=True)

    if ctl is None or shp is None:
        print(f"  {verdict_badge('error')}  connection failed")
        return False

    ctl_code, _, _ = ctl
    shp_code, shp_body, shp_hdr = shp

    print(f"  control (benign multipart) : HTTP {ctl_code}")
    print(f"  shaped  (php2shell layout) : HTTP {shp_code}")

    if 300 <= ctl_code < 400:
        loc = ctl[2].get("location", "?")
        print(f"  {verdict_badge('redirect')}  control redirects → {loc}")
        print(c.dim("       re-run against the redirect target"))
        return False

    ctl_blocked = ctl_code == 403 and CF_BLOCK_MARKER in ctl[1].lower()
    shp_blocked = shp_code == 403 and CF_BLOCK_MARKER in shp_body.lower()

    if shp_blocked and not ctl_blocked:
        ray = shp_hdr.get("cf-ray", "")
        print(f"  {verdict_badge('protected')}  Cloudflare edge block" + (c.dim(f"  (ray {ray})") if ray else ""))
        return True

    if ctl_blocked:
        print(f"  {verdict_badge('inconclusive')}  benign multipart also blocked — something blocks all POSTs")
        return False

    if shp_code == 403:
        print(f"  {verdict_badge('inconclusive')}  403 but not a Cloudflare block page — another control fired")
        return False

    print(f"  {verdict_badge('open')}  exploit shape reached the origin")
    return False


def main() -> int:
    global c
    ap = argparse.ArgumentParser(description="php2shell WAF control check (non-destructive)")
    ap.add_argument("targets", nargs="*", help="URLs to probe (overrides --targets-file)")
    ap.add_argument("--targets-file", metavar="FILE",
                    help="file with one URL per line ('#' comments ok); "
                         "defaults to targets.txt next to the script or in the cwd")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = ap.parse_args()

    c = C(enabled=not args.no_color and sys.stdout.isatty())

    if args.targets:
        targets = args.targets
    else:
        path = args.targets_file or default_targets_file()
        if not path:
            ap.error("no targets given and no targets.txt found "
                     "(see targets.example.txt next to the script)")
        try:
            targets = load_targets(path)
        except OSError as e:
            ap.error(f"cannot read {path}: {e}")
        if not targets:
            ap.error(f"no targets in {path}")
        print(c.dim(f"loaded {len(targets)} target(s) from {path}"))

    banner()

    ok = 0
    results = []
    for t in targets:
        passed = probe(t)
        results.append((t, passed))
        ok += passed

    print(c.bold("\n──────────────────────── summary ────────────────────────"))
    for t, passed in results:
        mark = c.green("✓") if passed else c.red("✗")
        print(f"  {mark} {t}")
    print()
    if ok == len(results):
        print(c.bold(c.green(f"  {ok}/{len(results)} targets PROTECTED at the edge.")))
    else:
        print(c.bold(c.yellow(f"  {ok}/{len(results)} protected — {len(results) - ok} need attention.")))
    print(c.dim(f"  WAF ≠ patch: verify origin PHP versions ({PATCHED}).\n"))

    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
