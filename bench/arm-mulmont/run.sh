#!/bin/bash
# Builds the precompiles benchmark for master, crypto/main before the review fixes (PREV) and this
# commit, runs the related unit tests of this commit and compares the benchmarks.
set -euo pipefail
BASE=$1
PREV=$2
cd "$(git rev-parse --show-toplevel)"
echo "### host: $(uname -sm), $($CXX --version | head -1)"
if [ "$(uname -s)" = Darwin ]; then
  sysctl -n machdep.cpu.brand_string; NPROC=$(sysctl -n hw.ncpu)
else
  (lscpu | grep -E "Model name|Vendor ID|^CPU\(s\)") || true; NPROC=$(nproc)
fi
git worktree add --detach ../base "$BASE" > /dev/null
git worktree add --detach ../prev "$PREV" > /dev/null
ln -s "$PWD" ../head
for v in base prev head; do
  cmake -S ../$v -B ../build-$v -DCMAKE_BUILD_TYPE=Release -DEVMONE_TESTING=ON > ../cfg-$v.log
  cmake --build ../build-$v --target evmone-precompiles-bench -j$NPROC > ../build-$v.log
done
cmake --build ../build-head --target evmone-unittests -j$NPROC > ../build-head-tests.log
../build-head/bin/evmone-unittests --gtest_filter='*expmod*:*modarith*:*secp256*:*bn254*:*ecc*' | tail -3
python3 bench/arm-mulmont/compare.py 5 base=../build-base/bin/evmone-precompiles-bench \
  prev=../build-prev/bin/evmone-precompiles-bench head=../build-head/bin/evmone-precompiles-bench \
  | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
