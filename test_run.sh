#!/usr/bin/env bash

./injector/build/prov start --path "."
./injector/build/prov exec "./test_scripts/first_exec" --path "."
./injector/build/prov exec "fortune | cowsay" --path "."
./injector/build/prov exec "./test_scripts/second_exec" --path "."
./injector/build/prov end
