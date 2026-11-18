#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# vendor/snappy reads unaligned u32 through a plain pointer cast (get_unaligned_le32); that is benign on the
# targets we build for and would otherwise halt every snappy decode.
UB_RELAX="-fno-sanitize=alignment"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# xfrpc has no library target: its CMake builds one executable from the source list below. We compile
# the same sources (minus main.c, which only wraps xfrpc_main) into objects, once instrumented for
# fuzzing and once with the project's normal flags for the functional oracle. Plain build, no cmake:
# CMake's wolfSSL probing and -Werror add nothing here, and the code paths are identical (OpenSSL).
SOURCES="client.c config.c control.c ini.c toml_parser.c vendor/tomlc17/tomlc17.c crypto_stream.c
  vendor/snappy/snappy.c oidc_auth.c msg.c xfrpc.c debug.c zip.c commandline.c crypto.c utils.c
  wire_v2.c aead_stream.c common.c login.c tls.c health_check.c proxy_tcp.c proxy_udp.c proxy.c
  tcpmux.c visitor.c xtcp_visitor.c xtcp_client.c nathole.c tcp_redir.c mongoose.c
  quic_client_transport.c plugins/telnetd.c plugins/instaloader.c plugins/httpd.c plugins/youtubedl.c"
DEFS="-D_GNU_SOURCE -Wno-everything"
LIBS="-levent -levent_openssl -ljson-c -lz -lssl -lcrypto -lpthread -lm -lcrypt -ldl"

FUZZ_DIR="$SRC/mayhem/build-fuzz"
TEST_DIR="$SRC/mayhem/build-tests"
mkdir -p "$FUZZ_DIR" "$TEST_DIR"

compile_one() {   # compile_one <outdir> <source> <flags...>
  local out="$1" f="$2"; shift 2
  if [ "$f" = oidc_auth.c ]; then
    # oidc_auth.c uses a GCC nested function, which clang rejects: build it with gcc, without sanitizer flags.
    local a flags=()
    for a in "$@"; do case "$a" in -fsanitize*) ;; *) flags+=("$a") ;; esac; done
    gcc "${flags[@]}" -I"$SRC" -c "$SRC/$f" -o "$out/${f//\//_}.o"
    return
  fi
  $CC "$@" -I"$SRC" -c "$SRC/$f" -o "$out/${f//\//_}.o"
}
export -f compile_one
export SRC CC
compile_all() {   # compile_all <outdir> <flags...>
  local out="$1"; shift
  rm -rf "$out" && mkdir -p "$out"
  printf '%s\n' $SOURCES | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'compile_one "$@"' _ "$out" {} "$@"
}

# 1) The project, instrumented. -fsanitize=fuzzer-no-link goes in unconditionally so the fuzzed code
#    carries coverage even when SANITIZER_FLAGS is emptied.
compile_all "$FUZZ_DIR/obj" $SANITIZER_FLAGS $UB_RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 $DEFS
rm -f "$FUZZ_DIR"/libxfrpc.a "$FUZZ_DIR"/libxfrpc_noctl.a "$FUZZ_DIR"/libxfrpc_nologin.a
ar rcs "$FUZZ_DIR/libxfrpc.a" "$FUZZ_DIR"/obj/*.o
# fuzz_control_recv #includes control.c and login.c itself (to reset/seed their static state), and
# fuzz_msg_json #includes login.c, so they link libraries without those objects.
ar rcs "$FUZZ_DIR/libxfrpc_noctl.a" $(ls "$FUZZ_DIR"/obj/*.o | grep -v '/control\.c\.o$' | grep -v '/login\.c\.o$')
ar rcs "$FUZZ_DIR/libxfrpc_nologin.a" $(ls "$FUZZ_DIR"/obj/*.o | grep -v '/login\.c\.o$')
# fuzz_stun and fuzz_nathole_sid #include nathole.c (the STUN parser and the AES-CFB helpers are static).
rm -f "$FUZZ_DIR"/libxfrpc_nonat.a
ar rcs "$FUZZ_DIR/libxfrpc_nonat.a" $(ls "$FUZZ_DIR"/obj/*.o | grep -v '/nathole\.c\.o$')

# 2) Harnesses: a libFuzzer binary and a run-once -standalone reproducer for each, with LSan disabled
#    at build time (lsan_off.cc).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FUZZ_DIR/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_DIR/standalone_main.o"

build_harness() {   # build_harness <name> <lib>
  local name="$1" lib="$2"
  $CC $SANITIZER_FLAGS $UB_RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 $DEFS -I"$SRC" -I"$SRC/mayhem" $LIB_FUZZING_ENGINE \
      "$SRC/mayhem/$name.c" "$FUZZ_DIR/lsan_off.o" "$FUZZ_DIR/$lib" $LIBS -lstdc++ -o "$SRC/$name"
  $CC $SANITIZER_FLAGS $UB_RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 $DEFS -I"$SRC" -I"$SRC/mayhem" \
      "$SRC/mayhem/$name.c" "$FUZZ_DIR/standalone_main.o" "$FUZZ_DIR/lsan_off.o" "$FUZZ_DIR/$lib" $LIBS -lstdc++ \
      -o "$SRC/$name-standalone"
}
build_harness fuzz_msg_json libxfrpc_nologin.a
build_harness fuzz_wire_v2 libxfrpc.a
build_harness fuzz_stream_codec libxfrpc.a
build_harness fuzz_control_recv libxfrpc_noctl.a
build_harness fuzz_socks5 libxfrpc_noctl.a
build_harness fuzz_xdpi libxfrpc_noctl.a
build_harness fuzz_stun libxfrpc_nonat.a
build_harness fuzz_nathole_sid libxfrpc_nonat.a

# fuzz_config is a raw file-input target (the loader calls exit() on bad config), so it has a main().
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 $DEFS -I"$SRC" -I"$SRC/mayhem" \
    "$SRC/mayhem/fuzz_config.c" "$FUZZ_DIR/lsan_off.o" "$FUZZ_DIR/libxfrpc.a" $LIBS -lstdc++ -o "$SRC/fuzz_config"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 $DEFS -DMAYHEM_FORCE_TOML -I"$SRC" -I"$SRC/mayhem" \
    "$SRC/mayhem/fuzz_config.c" "$FUZZ_DIR/lsan_off.o" "$FUZZ_DIR/libxfrpc.a" $LIBS -lstdc++ -o "$SRC/fuzz_config_toml"

# 3) The oracle: a known-answer probe linked against a separate, uninstrumented build (normal flags).
compile_all "$TEST_DIR/obj" -O2 $COVERAGE_FLAGS $DEFS
rm -f "$TEST_DIR/libxfrpc.a"
ar rcs "$TEST_DIR/libxfrpc.a" "$TEST_DIR"/obj/*.o
$CC -O2 $COVERAGE_FLAGS $DEFS -I"$SRC" "$SRC/mayhem/kat_xfrpc.c" "$TEST_DIR/libxfrpc.a" $LIBS \
    -o "$TEST_DIR/kat_xfrpc"
