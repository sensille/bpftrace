#!/bin/bash
#
# Test that debuginfod integration works with blazesym.
#
# This test:
# 1. Verifies the binary was built with debuginfod support
# 2. Strips debug info from a test program
# 3. Pre-populates the debuginfod cache with the debug info
# 4. Runs bpftrace against the stripped binary
# 5. Verifies that file/line info is resolved via debuginfod
#

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Must be run as root" >&2
  exit 1
fi

TESTS_DIR="$(dirname "${BASH_SOURCE[0]}")"
DIR="$(cd "$TESTS_DIR" > /dev/null && pwd)"
BPFTRACE=${1:-${BPFTRACE_EXECUTABLE:-$DIR/../src/bpftrace}}
# Derive build test directory from bpftrace binary location
BUILD_DIR="$(dirname "$(dirname "$BPFTRACE")")"
TESTPROG="$BUILD_DIR/tests/testprogs/uprobe_loop"

# Check bpftrace was built with debuginfod support
INFO_OUTPUT=$("$BPFTRACE" --info 2>&1)
if ! echo "$INFO_OUTPUT" | grep -q "libdebuginfod (debuginfod support): yes"; then
  echo "SKIP: bpftrace not built with debuginfod support"
  exit 0
fi

# Check bpftrace was built with blazesym support
if ! echo "$INFO_OUTPUT" | grep -q "blazesym (advanced symbolization): yes"; then
  echo "SKIP: bpftrace not built with blazesym support"
  exit 0
fi

# Check test program exists and has a build ID
if [ ! -x "$TESTPROG" ]; then
  echo "FAIL: test program not found: $TESTPROG" >&2
  exit 1
fi

BUILD_ID=$(readelf -n "$TESTPROG" 2>/dev/null | grep "Build ID:" | awk '{print $NF}')
if [ -z "$BUILD_ID" ]; then
  echo "SKIP: test program has no build ID (rebuild with -Wl,--build-id)"
  exit 0
fi

echo "Test program: $TESTPROG"
echo "Build ID: $BUILD_ID"

# Create temp dir for test artifacts
TMPDIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

# Strip the test binary
STRIPPED="$TMPDIR/uprobe_loop.stripped"
cp "$TESTPROG" "$STRIPPED"
strip --strip-debug "$STRIPPED"

# Verify stripped binary has no debug info
if readelf -S "$STRIPPED" 2>/dev/null | grep -q "\.debug_"; then
  echo "FAIL: stripped binary still has debug sections" >&2
  exit 1
fi

# Pre-populate debuginfod cache
CACHE_DIR="$TMPDIR/debuginfod_cache"
CACHE_ENTRY="$CACHE_DIR/$BUILD_ID"
mkdir -p "$CACHE_ENTRY"
# Use the full unstripped binary as debug info — ElfResolver needs
# proper code sections, not just debug-only output from objcopy.
cp "$TESTPROG" "$CACHE_ENTRY/debuginfo"

echo "Cache dir: $CACHE_DIR"

# The process_dispatch_cb only fires for process-based symbolization
# (blaze_symbolize_process_abs_addrs), not ELF-based. Use NONE cache
# to force the process symbolization path.
export BPFTRACE_CACHE_USER_SYMBOLS=NONE

# First, verify that WITHOUT debuginfod, the stripped binary does NOT
# show file/line info
echo ""
echo "=== Test 1: Stripped binary without debuginfod should NOT have file:line ==="
OUTPUT_NO_DI=$(
  DEBUGINFOD_URLS="" \
    "$BPFTRACE" -e "u:${STRIPPED}:uprobeFunction1 { printf(\"%s\n\", ustack(1)); exit(); }" \
    -c "$STRIPPED" 2>&1 || true
)

echo "Output: $OUTPUT_NO_DI"
if echo "$OUTPUT_NO_DI" | grep -qE '@.*\.c:[0-9]+'; then
  echo "FAIL: stripped binary without debuginfod unexpectedly has file:line info"
  exit 1
fi
echo "PASS: No file:line info without debuginfod (as expected)"

# Second, verify that WITH debuginfod (via cache), the stripped binary
# DOES show file/line info
echo ""
echo "=== Test 2: Stripped binary with debuginfod cache SHOULD have file:line ==="
OUTPUT_DI=$(
  DEBUGINFOD_URLS="http://127.0.0.1:1" \
  DEBUGINFOD_CACHE_PATH="$CACHE_DIR" \
    "$BPFTRACE" -e "u:${STRIPPED}:uprobeFunction1 { printf(\"%s\n\", ustack(1)); exit(); }" \
    -c "$STRIPPED" 2>&1 || true
)

echo "Output: $OUTPUT_DI"
if echo "$OUTPUT_DI" | grep -qE '@.*\.c:[0-9]+'; then
  echo "PASS: debuginfod resolved file:line info for stripped binary"
else
  echo "FAIL: debuginfod did not resolve file:line info"
  echo "Expected output containing '@<file>.c:<line>'"
  exit 1
fi

echo ""
echo "All debuginfod tests passed."
