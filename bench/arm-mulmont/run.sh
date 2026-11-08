#!/bin/bash
# Builds the precompiles benchmark for master, master with each portable change of the WIP, the WIP
# with the C almost Montgomery multiplication and the WIP (assembly on aarch64), and compares them.
# Also runs the related unit tests of the WIP.
set -euo pipefail
BASE=$1
cd "$(git rev-parse --show-toplevel)"
echo "### host: $(uname -sm), $($CXX --version | head -1)"
if [ "$(uname -s)" = Darwin ]; then
  sysctl -n machdep.cpu.brand_string; NPROC=$(sysctl -n hw.ncpu)
else
  (lscpu | grep -E "Model name|Vendor ID|^CPU\(s\)") || true; NPROC=$(nproc)
fi
P=lib/evmone_precompiles
variant() {  # name file...: master with the WIP versions of the files
  git worktree add --detach ../$1 "$BASE" > /dev/null
  shift_name=$1; shift
  for f in "$@"; do git show HEAD:$f > ../$shift_name/$f; done
}
variant safegcd $P/modarith.hpp
variant ecc $P/ecc.hpp
variant p256 $P/secp256r1.cpp
git worktree add --detach ../base "$BASE" > /dev/null
git worktree add --detach ../wip_c HEAD > /dev/null
perl -pi -e 's/^#ifdef __aarch64__$/#if 0/' ../wip_c/$P/mulmod.hpp
ln -s "$PWD" ../head
for v in base safegcd ecc p256 wip_c head; do
  cmake -S ../$v -B ../build-$v -DCMAKE_BUILD_TYPE=Release -DEVMONE_TESTING=ON > ../cfg-$v.log
  cmake --build ../build-$v --target evmone-precompiles-bench -j$NPROC > ../build-$v.log
done
cmake --build ../build-head --target evmone-unittests -j$NPROC > ../build-head-tests.log
../build-head/bin/evmone-unittests --gtest_filter='*expmod*:*modarith*:*secp256*:*bn254*:*ecc*' | tail -3
python3 bench/arm-mulmont/compare.py 5 base=../build-base/bin/evmone-precompiles-bench \
  safegcd=../build-safegcd/bin/evmone-precompiles-bench ecc=../build-ecc/bin/evmone-precompiles-bench \
  p256=../build-p256/bin/evmone-precompiles-bench wip_c=../build-wip_c/bin/evmone-precompiles-bench \
  head=../build-head/bin/evmone-precompiles-bench | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
