#!/usr/bin/env bash

./prov start --path "example_path"
./prov exec "fortune | cowsay" --path "."
./prov end
