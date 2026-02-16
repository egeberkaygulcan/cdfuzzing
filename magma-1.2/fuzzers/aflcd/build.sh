#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

if [ ! -d "$FUZZER/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

cd "$FUZZER/repo"
make clean  # Remove any existing object files from host
CC=clang make -j $(nproc) AFL_DRIFT_DETECT=1 AFL_NO_X86=1
CC=clang make -j $(nproc) -C llvm_mode

# compile afl_driver.cpp
"./afl-clang-fast++" $CXXFLAGS -std=c++11 -c "afl_driver.cpp" -fPIC -o "$OUT/afl_driver.o"
