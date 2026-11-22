#!/bin/sh
# Functional tests for pcapreport. Requires: python3 (to generate captures).
# Optional: valgrind (memory check), pdfinfo/qpdf (PDF validation).
# Usage: tests/run_tests.sh   (from the project root, after `make`)
set -u
BIN=${BIN:-./pcapreport}
D=tests/data
O=tests/out
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
expect_rc() { # name expected_rc actual_rc
    if [ "$2" = "$3" ]; then ok "$1 (exit $3)"; else bad "$1: expected exit $2, got $3"; fi
}
has() { # name file pattern
    if grep -q -- "$3" "$2"; then ok "$1"; else bad "$1: '$3' not found in $2"; fi
}

[ -x "$BIN" ] || { echo "build first: make"; exit 1; }
rm -rf "$O"; mkdir -p "$O"
python3 tests/gen_pcap.py "$D" >/dev/null || { echo "cannot generate test data"; exit 1; }

echo "== classic pcap, all scenarios"
"$BIN" -q -s -o "$O/sample" "$D/sample.pcap" >"$O/sample.txt"; expect_rc "sample.pcap" 0 $?
for f in report.pdf 01_throughput.png 02_packet_rate.png 03_protocols.png 04_packet_sizes.png \
         05_top_talkers.png 06_top_services.png 07_tcp_flags.png 08_tcp_events.png; do
    [ -s "$O/sample/$f" ] && ok "output $f" || bad "output $f missing"
done
head -c 5 "$O/sample/report.pdf" | grep -q '%PDF-' && ok "PDF magic" || bad "PDF magic"
head -c 8 "$O/sample/01_throughput.png" | od -An -tx1 | grep -q '89 50 4e 47' && ok "PNG magic" || bad "PNG magic"
has "port scan detected"        "$O/sample.txt" "Port scan: TCP port scan: 10.0.0.66 -> 10.0.0.20"
has "host sweep detected"       "$O/sample.txt" "Host sweep on TCP/445"
has "SYN flood detected"        "$O/sample.txt" "SYN flood against 10.0.0.30:80"
has "beaconing detected"        "$O/sample.txt" "Periodic connections 10.0.0.15 -> 203.0.113.50:8443"
has "amplification detected"    "$O/sample.txt" "UDP amplification"
has "invalid flags detected"    "$O/sample.txt" "invalid flag combinations"
has "retransmissions detected"  "$O/sample.txt" "Lossy TCP connection 10.0.0.11"
has "zero window detected"      "$O/sample.txt" "zero-window"
has "LAND detected"             "$O/sample.txt" "LAND packets"
has "malformed counted"         "$O/sample.txt" "malformed: 2 "
if command -v qpdf >/dev/null 2>&1; then
    qpdf --check "$O/sample/report.pdf" >/dev/null 2>&1 && ok "qpdf --check" || bad "qpdf --check"
fi

echo "== pcapng (big endian, ns resolution) gives identical statistics"
"$BIN" -q -s --no-png -o "$O/ng" "$D/sample_be_ns.pcapng" >"$O/ng.txt"; expect_rc "pcapng" 0 $?
grep -v '^file ' "$O/sample.txt" >"$O/a.txt"; grep -v '^file ' "$O/ng.txt" >"$O/b.txt"
cmp -s "$O/a.txt" "$O/b.txt" && ok "pcap == pcapng summary" || { bad "pcap vs pcapng differ"; diff "$O/a.txt" "$O/b.txt"; }

echo "== Linux cooked capture with IPv6"
"$BIN" -q -s --no-pdf -o "$O/sll" "$D/sll_ipv6.pcap" >"$O/sll.txt"; expect_rc "sll_ipv6.pcap" 0 $?
has "SLL packets decoded" "$O/sll.txt" "tcp: 50 pkts"

echo "== damaged inputs"
"$BIN" -q -s --no-png -o "$O/tr" "$D/truncated.pcap" >"$O/tr.txt"; expect_rc "truncated file" 0 $?
has "truncation reported" "$O/tr.txt" "truncated (last record incomplete)"
"$BIN" -q -s --no-png -o "$O/co" "$D/corrupt.pcap" >"$O/co.txt"; expect_rc "corrupt record header" 0 $?
has "corruption reported" "$O/co.txt" "stopped after 1 packets"
"$BIN" -q -o "$O/x" "$D/garbage.bin" 2>/dev/null; expect_rc "garbage only" 2 $?
"$BIN" -q -o "$O/x" "$D/empty.pcap" 2>/dev/null; expect_rc "empty only" 2 $?
"$BIN" -q -o "$O/x" /nonexistent.pcap 2>/dev/null; expect_rc "missing file" 2 $?
"$BIN" -q -o "$O/x" "$D" 2>/dev/null; expect_rc "directory as input" 2 $?
"$BIN" -q -s --no-png -o "$O/mix" "$D/sample.pcap" "$D/garbage.bin" "$D/sll_ipv6.pcap" >"$O/mix.txt" 2>/dev/null
expect_rc "mixed good + bad inputs" 3 $?
has "multi-file merge" "$O/mix.txt" "files: 3"

echo "== stdin and option handling"
"$BIN" -q -s --no-png -o "$O/stdin" - <"$D/sample.pcap" >"$O/stdin.txt"; expect_rc "stdin input" 0 $?
"$BIN" >/dev/null 2>&1; expect_rc "no arguments" 1 $?
"$BIN" --top 0 "$D/sample.pcap" >/dev/null 2>&1; expect_rc "invalid --top" 1 $?
"$BIN" --no-pdf --no-png "$D/sample.pcap" >/dev/null 2>&1; expect_rc "nothing to output" 1 $?
"$BIN" --bogus "$D/sample.pcap" >/dev/null 2>&1; expect_rc "unknown option" 1 $?
"$BIN" - - <"$D/sample.pcap" >/dev/null 2>&1; expect_rc "stdin twice" 1 $?
"$BIN" -q --max-flows 10 --no-png -o "$O/lim" -s "$D/sample.pcap" >"$O/lim.txt"; expect_rc "flow limit" 0 $?
has "flow limit reported" "$O/lim.txt" "Flow/host table limit reached"
touch "$O/afile"
"$BIN" -q -o "$O/afile" "$D/sample.pcap" 2>/dev/null; expect_rc "output dir is a file" 4 $?

if command -v valgrind >/dev/null 2>&1; then
    echo "== valgrind (leaks / invalid accesses)"
    for f in sample.pcap truncated.pcap corrupt.pcap sll_ipv6.pcap; do
        valgrind -q --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=all \
            "$BIN" -q -o "$O/vg" "$D/$f" >/dev/null 2>"$O/vg.log"
        rc=$?
        [ $rc -ne 99 ] && ok "valgrind clean: $f" || { bad "valgrind: $f"; cat "$O/vg.log"; }
    done
fi

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
