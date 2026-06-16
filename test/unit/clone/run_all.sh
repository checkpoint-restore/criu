#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building tests..."
make clean
make all

echo ""
echo "Running tests..."
make check
