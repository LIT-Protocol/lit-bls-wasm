#!/bin/bash

wasm-pack build --target=web

cd convertWasmToJs
python3 convert_wasm_to_js.py