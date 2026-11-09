#!/bin/bash
# Builds the n = 4k squaring prototype (bench/arm-mulmont/sqr) on top of this commit's
# mul_mont.cpp, checks it bit-exactly against the reference and times it against
# mul_amm_asm(x, x).
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
P=bench/arm-mulmont/sqr
FL="-O3 -DNDEBUG -std=c++20 -fno-stack-protector -falign-functions=64 -Ilib -I$L -I$INTX -Ibench/arm-mulmont/proto"
$CXX $FL -DMM_SRC="\"$PWD/$L/mul_mont.cpp\"" -c $P/sqr_proto.cpp -o ../p.o
$CXX $FL -c $P/sqr_bench.cpp -o ../b.o
$CXX $FL -c bench/arm-mulmont/proto/ref.cpp -o ../ref.o
$CXX $FL -c $L/mulmod.cpp -o ../mulmod.o
$CXX ../b.o ../ref.o ../p.o ../mulmod.o -o ../sb
../sb test
for i in 1 2; do ../sb 15 | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"; done
