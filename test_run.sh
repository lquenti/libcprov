#!/usr/bin/env bash

./injector/build/prov start --path "."
./injector/build/prov exec "fortune | cowsay" --path "."
./injector/build/prov end
