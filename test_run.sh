#!/usr/bin/env bash

./build/injector/prov start --path "."
./build/injector/prov exec "./test_scripts/first_exec" --path "."
./build/injector/prov exec "./test_scripts/second_exec" --path "."
./build/injector/prov end
