#!/bin/bash
# Builds the 4-word AMM prototypes (bench/arm-mulmont/proto) on top of this commit's mul_mont.cpp,
# checks them bit-exactly against the reference and times the production proc, the blst-order
# rows and the squaring.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
echo "### host: $(uname -sm), $($CXX --version | head -1)"
if [ "$(uname -s)" = Darwin ]; then
  sysctl -n machdep.cpu.brand_string
else
  (lscpu | grep -E "Model name|Vendor ID|^CPU\(s\)") || true
  sudo sysctl -w kernel.perf_event_paranoid=1 > /dev/null || true
fi
cmake -S . -B ../build -DCMAKE_BUILD_TYPE=Release > ../cfg.log
INTX=$(dirname "$(dirname "$(find ~/.hunter -name intx.hpp -path '*Install*' | head -1)")")
L=lib/evmone_precompiles
P=bench/arm-mulmont/proto
FL="-O3 -DNDEBUG -std=c++20 -fno-stack-protector -falign-functions=64 -Ilib -I$L -I$INTX"
$CXX $FL -DMM_SRC="\"$PWD/$L/mul_mont.cpp\"" -c $P/mm_proto.cpp -o ../mm.o
$CXX $FL -c $P/bench_proto.cpp -o ../b.o
$CXX $FL -c $P/ref.cpp -o ../ref.o
$CXX $FL -c $L/mulmod.cpp -o ../mulmod.o
$CXX ../b.o ../ref.o ../mm.o ../mulmod.o -o ../bp
../bp test 1000000
../bp 30 | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
