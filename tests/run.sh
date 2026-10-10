#!/bin/sh
# Copyright 2026 Daher Alfawares
# SPDX-License-Identifier: Apache-2.0

# Builds Ember's example and checks, and runs them all against the Firebase emulators:
# Firestore on localhost:8080 and Auth on localhost:9099, unless FIRESTORE_EMULATOR_HOST
# and FIREBASE_AUTH_EMULATOR_HOST say otherwise. The parity check with Google's JS SDK
# needs Node, and installs the SDK into tests/parity the first time.

set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
export FIRESTORE_EMULATOR_HOST=${FIRESTORE_EMULATOR_HOST:-localhost:8080}
export FIREBASE_AUTH_EMULATOR_HOST=${FIREBASE_AUTH_EMULATOR_HOST:-localhost:9099}
tls=$(pkg-config --cflags --libs botan-3)

mkdir -p build
g++ -std=c++23 -Wall -Wextra -Werror -Iinclude examples/listen.cpp -o build/listen $tls
g++ -std=c++23 -Wall -Wextra -Werror -Iinclude tests/test.cpp -o build/test $tls
# OpenSSL builds too, and must keep building.
g++ -std=c++23 -Wall -Wextra -Werror -DEMBER_TLS_OPENSSL -Iinclude examples/listen.cpp -o build/listen-openssl -lssl -lcrypto

echo "== auth, get, listening"
build/test
echo "== a dropped connection"
tests/emulator.sh
echo "== the same as Google's JS SDK"
[ -d tests/parity/node_modules/firebase ] || (cd tests/parity && npm install --no-audit --no-fund >/dev/null)
node tests/parity/parity.mjs
