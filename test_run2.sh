#!/usr/bin/env bash

./injector/build/prov start --path "."
#./injector/build/prov exec "./test_scripts/test_hooks_synthetic" --path "."
#./injector/build/prov exec "./test_scripts/test_hooks_synthetic_clang" --path "."
#./injector/build/prov exec "python3 ./test_scripts/test_hooks_synthetic.py" --path "."
#./injector/build/prov exec "Rscript ./test_scripts/test_hooks_synthetic.r" --path "."
./injector/build/prov exec "julia ./test_scripts/test_hooks_synthetic.jl" --path "."
#./injector/build/prov exec "./test_scripts/test_hooks_synthetic_go" --path "."
#./injector/build/prov exec "./test_scripts/test_fork_execv" --path "."
#./injector/build/prov exec "./test_scripts/test_multithreading" --path "."
./injector/build/prov end
