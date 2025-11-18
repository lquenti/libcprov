#!/usr/bin/env bash

./injector/prov start --path "."
./injector/prov exec "fortune | cowsay" --path "."
./injector/prov end
