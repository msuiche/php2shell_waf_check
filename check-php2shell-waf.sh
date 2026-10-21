#!/usr/bin/env bash
# check-php2shell-waf.sh — non-destructive WAF/mitigation validator for
# CVE-2026-109618 / CVE-2026-109619 ("php2shell").
#
# For each target URL it sends TWO tiny multipart/form-data POSTs:
#
#   1. control  — a benign one-field form (~10 bytes). Expected to pass the
#                 edge and be answered by the origin (404/200/302 all fine).
#   2. shaped   — the php2shell exploit *shape* at harmless size (~8 KB):
#                 PHP_SESSION_UPLOAD_PROGRESS field, array fields, and two
#                 file parts (the CVE-2026-109619 two-file layout that
#                 strands the stale outer pointer). No oversized allocations,
#                 no grooming volume — PHP parses this in microseconds.
#
# Verdict logic per target:
#   control passes + shaped 403 with a Cloudflare block page  -> PROTECTED (edge rule fires)
#   control passes + shaped passes                            -> NOT BLOCKED at edge (origin reachable with exploit shape)
#   control also blocked                                      -> INCONCLUSIVE (something blocks all multipart POSTs)
#   control redirects                                         -> noted; re-run against the redirect target
#
# This validates the COMPENSATING CONTROL (WAF) only. It does not tell you
# the origin PHP version and it does not prove exploitability — patch status
# still has to be verified server-side (e.g. MyKinsta -> Tools -> PHP version).
#
# Usage:
#   ./check-php2shell-waf.sh https://example.com/upload.php [url...]
#   ./check-php2shell-waf.sh --targets-file my-targets.txt
#   ./check-php2shell-waf.sh                 # reads targets.txt next to the
#                                            # script or in the cwd
#
# Targets file format: one URL per line, '#' comments and blanks ignored.
# See targets.example.txt next to this script.
#
# Exit code: 0 if every target is PROTECTED, 1 otherwise.

set -u

CF_BLOCK_MARKER='Attention Required! | Cloudflare'
TMPDIR_PROBE="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_PROBE"' EXIT

# tiny file parts for the shaped request
head -c 4096 /dev/urandom > "$TMPDIR_PROBE/f1.bin"
head -c 4096 /dev/urandom > "$TMPDIR_PROBE/f2.bin"

send_control() { # url -> prints "code bodyfile headerfile"
  local url="$1"
  curl -sS -m 20 -o "$TMPDIR_PROBE/ctl.body" -D "$TMPDIR_PROBE/ctl.hdr" \
       -w '%{http_code}' -X POST -F 'tolmo_probe=benign' "$url" 2>/dev/null || echo "000"
}

send_shaped() { # url -> prints code; body/hdr in tmp
  local url="$1"
  curl -sS -m 20 -o "$TMPDIR_PROBE/shp.body" -D "$TMPDIR_PROBE/shp.hdr" \
       -w '%{http_code}' -X POST \
       -H 'Cookie: PHPSESSID=wafprobe0001' \
       -F 'PHP_SESSION_UPLOAD_PROGRESS=probe' \
       -F 't[]=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
       -F 't[]=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' \
       -F 't[]=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC' \
       -F "file1=@$TMPDIR_PROBE/f1.bin;filename=first.bin;type=application/octet-stream" \
       -F "file2=@$TMPDIR_PROBE/f2.bin;filename=second.bin;type=application/octet-stream" \
       "$url" 2>/dev/null || echo "000"
}

is_cf_block() { grep -qi "$CF_BLOCK_MARKER" "$1" 2>/dev/null; }

probe() {
  local url="$1"
  local ctl shp
  ctl="$(send_control "$url")"
  shp="$(send_shaped "$url")"

  printf '%-55s control=%s shaped=%s  ' "$url" "$ctl" "$shp"

  if [ "$ctl" = "000" ] || [ "$shp" = "000" ]; then
    echo "ERROR (connection failed)"
    return 1
  fi

  if [ "$ctl" -ge 300 ] && [ "$ctl" -lt 400 ]; then
    loc="$(grep -i '^location:' "$TMPDIR_PROBE/ctl.hdr" | tr -d '\r' | awk '{print $2}')"
    echo "REDIRECT on control -> ${loc:-unknown} (re-run against target)"
    return 1
  fi

  if [ "$shp" = "403" ] && is_cf_block "$TMPDIR_PROBE/shp.body"; then
    echo "PROTECTED (Cloudflare edge block)"
    return 0
  fi

  if [ "$ctl" = "403" ] && is_cf_block "$TMPDIR_PROBE/ctl.body"; then
    echo "INCONCLUSIVE (benign multipart also blocked)"
    return 1
  fi

  if [ "$shp" != "403" ]; then
    echo "NOT BLOCKED (exploit shape reached origin)"
    return 1
  fi

  echo "BLOCKED by non-Cloudflare 403 (check body: $TMPDIR_PROBE/shp.body)"
  return 1
}

main() {
  local targets=() file=""
  if [ "${1:-}" = "--targets-file" ]; then
    file="${2:-}"
    [ -f "$file" ] || { echo "error: cannot read targets file: $file" >&2; exit 2; }
  elif [ $# -eq 0 ]; then
    local here; here="$(cd "$(dirname "$0")" && pwd)"
    for cand in "$here/targets.txt" "$PWD/targets.txt"; do
      [ -f "$cand" ] && file="$cand" && break
    done
    [ -n "$file" ] || { echo "error: no targets given and no targets.txt found (see targets.example.txt)" >&2; exit 2; }
  fi

  if [ -n "$file" ]; then
    while IFS= read -r line; do
      line="${line%%#*}"; line="$(echo "$line" | tr -d '[:space:]')"
      [ -n "$line" ] && targets+=("$line")
    done < "$file"
    echo "loaded ${#targets[@]} target(s) from $file"
  else
    targets=("$@")
  fi
  [ "${#targets[@]}" -gt 0 ] || { echo "error: empty target list" >&2; exit 2; }

  echo "php2shell WAF control check — $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "payloads are ~8 KB and harmless; this validates edge rules, not the patch."
  echo

  local fails=0
  for t in "${targets[@]}"; do
    probe "$t" || fails=$((fails+1))
  done

  echo
  if [ "$fails" -eq 0 ]; then
    echo "All targets PROTECTED at the edge. Still verify origin PHP versions (8.5.12/8.4.27/8.3.36/8.2.35) — WAF is defense-in-depth, not a fix."
  else
    echo "$fails target(s) need attention."
  fi
  [ "$fails" -eq 0 ]
}

main "$@"
