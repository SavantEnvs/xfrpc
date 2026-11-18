#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# The functional oracle: mayhem/build-tests/kat_xfrpc links the real xfrpc objects (normal flags, no
# sanitizers) and prints known-answer results; each subcommand's stdout is compared with golden text
# (key/CFB/transcript values were cross-checked against python hashlib and openssl).
KAT="$SRC/mayhem/build-tests/kat_xfrpc"
[ -x "$KAT" ] || { echo "missing $KAT: mayhem/build.sh did not build it" >&2; emit_ctrf xfrpc-kat 0 1 0; exit 1; }

passed=0; failed=0
check() {   # check <name> <expected> <args...>
  local name="$1" want="$2"; shift 2
  local got
  got="$("$KAT" "$@" 2>/dev/null)" && [ "$got" = "$want" ] && { passed=$((passed+1)); echo "ok   $name"; return; }
  failed=$((failed+1)); echo "FAIL $name"; printf 'want:\n%s\ngot:\n%s\n' "$want" "$got"
}

check config_ini 'server_addr=your_server_ip
server_port=7000
tcp_mux=1
heartbeat_interval=30
token=(none)
proxy=ssh type=tcp local_ip=127.0.0.1 local_port=22 remote_port=6128' config xfrpc_min.ini

check config_toml 'server_addr=0.0.0.0
server_port=7000
tcp_mux=1
heartbeat_interval=30
token=12345678
proxy=ssh type=tcp local_ip=127.0.0.1 local_port=22 remote_port=6001' config xfrpc_min.toml

check json_messages 'login_resp version=0.61.0 run_id=abcdef0123456789 error=
new_proxy run_id=r1 name=web remote_port=8080 error=
start_work_conn proxy_name=ssh
udp content=aGVsbG8= laddr=10.0.0.1:53 raddr=10.0.0.2:5353
bad_json=rejected' json

check wire_v2 'req_work_conn_frame=001000000000000400077b7d
parse n=12 type=16 plen=4
v1=7200000000000000027b7d
partial=0
bad_flags=-1
server_hello rc=0 alg=aes-256-gcm
server_hello_bad rc=-1
transcript=3cdb27e7ad61990aa2f1a6ca8d76caa6456ac93bf0f17f0a3e5ac16af4a427be' wire

check codecs 'key=c16a8f63832926cee123eea29f95d670
cfb_decrypt_hello_world=028aafae5bcd832ebfbc5c
snappy rc=0 len=5 text=hello
snappy_small_buffer rc=-1
snappy_compressed=171468656c6c6f20420600' codec

check tcpmux 'mux_data_syn=00000001000000050000012c
validate=1
mux_window_ack=000100020000000700000000
validate_bad_version=0' mux

emit_ctrf xfrpc-kat "$passed" "$failed" 0
