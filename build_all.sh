#!/usr/bin/env bash
set -euo pipefail

mkdir -p build
cd build

if [ "${1:-}" = "hpc" ]; then
    module load gcc/14.2.0
    export CC="$(which gcc)"
    export CXX="$(which g++)"
    export LDFLAGS="-ldl"
fi

cmake .. \
  -DCMAKE_CXX_STANDARD=23 \
  -DCMAKE_CXX_STANDARD_REQUIRED=ON \
  -DCMAKE_CXX_EXTENSIONS=ON \
  -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS:-}"

cmake --build . -- -j"$(nproc)"
