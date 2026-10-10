#!/bin/sh
# Copyright 2026 Daher Alfawares
# SPDX-License-Identifier: Apache-2.0

# Listens to a document on the Firestore emulator and checks what the listener says:
#
#   1. the document as it is, once;
#   2. a change, once;
#   3. the connection cut through a proxy, the document changed while it's down, and
#      the listener back from where it stopped: that change once, nothing twice;
#   4. the connection cut with nothing changed: nothing told;
#   5. the document deleted: told it no longer exists.
#
# Needs the emulator on localhost:8080 (FIRESTORE_EMULATOR_HOST to change it), socat
# for the proxy, and build/listen, from:
#
#   g++ -std=c++23 -Iinclude examples/listen.cpp -o build/listen $(pkg-config --cflags --libs botan-3)

set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
emulator=${FIRESTORE_EMULATOR_HOST:-localhost:8080}
project=demo-ember
proxy=18080
path="tests/one-$$"
api="http://$emulator/v1/projects/$project/databases/(default)/documents"
out=$(mktemp)
err=$(mktemp)

write() {
	curl -sf -X PATCH -H "Authorization: Bearer owner" -H "Content-Type: application/json" \
		"$api/$path" -d "{\"fields\":{\"step\":{\"integerValue\":\"$1\"}}}" >/dev/null
}
start_proxy() {
	socat TCP-LISTEN:$proxy,reuseaddr,fork TCP:$emulator &
	proxy_pid=$!
	sleep 0.5
}
stop_proxy() {
	kill "$proxy_pid"
	wait "$proxy_pid" 2>/dev/null || true
	# socat's children hold the connections it made; cut those too.
	pkill -f "socat TCP-LISTEN:$proxy" 2>/dev/null || true
}
lines() { wc -l <"$out" | tr -d ' '; }
expect() {
	if [ "$(lines)" != "$1" ]; then
		echo "FAILED: $2: expected $1 lines, got $(lines)" >&2
		cat "$out" "$err" >&2
		exit 1
	fi
	echo "ok: $2"
}

write 1
start_proxy
FIRESTORE_EMULATOR_HOST=localhost:$proxy "$here/build/listen" "$project" "$path" >"$out" 2>"$err" &
listener=$!
trap 'kill $listener 2>/dev/null; stop_proxy 2>/dev/null; rm -f "$out" "$err"' EXIT

sleep 2
expect 1 "the document as it is"
grep -q '"step":1' "$out"

write 2
sleep 2
expect 2 "a change"

stop_proxy
write 3
sleep 1
start_proxy
sleep 5
expect 3 "a change made while the connection was down, told once after it's back"
grep -q '"step":3' "$out"
grep -q "from where it stopped" "$err"

stop_proxy
sleep 1
start_proxy
sleep 5
expect 3 "a dropped connection with nothing changed tells nothing"

curl -sf -X DELETE -H "Authorization: Bearer owner" "$api/$path" >/dev/null
sleep 2
expect 4 "the document deleted"
tail -1 "$out" | grep -q '"exists":false'

echo "all passed"
