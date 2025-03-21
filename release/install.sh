#!/bin/bash

readonly INSTALL_LIB_DIR="/lib/criu"
SCRIPT_DIR="$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)"

mkdir -p "$INSTALL_LIB_DIR"

for filename in $(ls "$SCRIPT_DIR/" | grep "lib*"); do
    cp "$SCRIPT_DIR/$filename" "$INSTALL_LIB_DIR"
done

cp "$SCRIPT_DIR/criu" /usr/local/sbin/criu
