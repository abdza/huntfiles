#!/bin/bash
export RUST_BACKTRACE=1 
export OPENSSL_DIR="/etc/ssl"
export OPEN_INCLUDE_DIR="/usr/include/openssl"
cross build --target x86_64-pc-windows-gnu
