#!/bin/bash
# Builds the precompiles benchmark of the base commit and of this commit, and compares them.
set -euo pipefail
BASE=$1
cd "$(git rev-parse --show-toplevel)"
echo "### host: $(uname -sm), $($CXX --version | head -1)"
if [ "$(uname -s)" = Darwin ]; then
  sysctl -n machdep.cpu.brand_string; NPROC=$(sysctl -n hw.ncpu)
else
  (lscpu | grep -E "Model name|Vendor ID|^CPU\(s\)") || true; NPROC=$(nproc)
fi
git worktree add --detach ../base "$BASE"
for t in base head; do
  src=.; [ $t = base ] && src=../base
  cmake -S $src -B ../build-$t -DCMAKE_BUILD_TYPE=Release -DEVMONE_TESTING=ON > ../cfg-$t.log
  cmake --build ../build-$t --target evmone-precompiles-bench -j$NPROC > ../build-$t.log
done
python3 bench/arm-mulmont/compare.py 7 ../build-base/bin/evmone-precompiles-bench \
  ../build-head/bin/evmone-precompiles-bench | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
