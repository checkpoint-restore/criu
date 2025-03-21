#!/bin/bash

set -euo pipefail

readonly INSTALL_LIB_DIR="/lib/criu"
readonly CRIU_REPO="/tmp/criu"
readonly CRIU_BUNDLE="/tmp/criu-bundle"

git clone https://github.com/castai/criu.git "$CRIU_REPO"
pushd "$CRIU_REPO"
    git checkout v4.0-patch
    make -j 15 install-criu install-compel
popd

mkdir "$CRIU_BUNDLE"
cp ./install.sh "$CRIU_BUNDLE"
cp "$CRIU_REPO/criu/criu" "$CRIU_BUNDLE"

# Grepping here skips libs like ld-linux-x86-64 and linux-vdso
/lib64/ld-linux-x86-64.so.2 --list "$CRIU_REPO/criu/criu" | grep "=>" >./libmap.txt

while IFS= read -r line; do
    filename="$(echo $line | awk '{print $1}')"
    source="$(echo $line | awk '{print $3}')"

    cp $source "$CRIU_BUNDLE"

    # Make sure the binary is loading the libraires it has been built with.
    # These must be placed in the INSTALL_LIB_DIR on the target system. See
    # install.sh
    patchelf --replace-needed "$filename" "$INSTALL_LIB_DIR/$filename" "$CRIU_BUNDLE/criu"
done <"./libmap.txt"

# Not all libraries that are necessary to run the binary are patched with
# --replace-needed, some binaries are being loaded from the system (for example
# /lib/x86_64-linux-gnu) and this is done by the loader. To get around this and
# use the specific libraries this binary was built from we must set the RPATH.
# --force-rpath is necessary otherwise patchelf will only set RUNPATH.
patchelf --set-rpath /lib/criu --force-rpath /tmp/criu-bundle/criu
