#!/bin/bash

cargo fmt
cargo clippy
cargo build
wasm-pack build --target=web
wasm-pack test --node