# Ember

**libember** — an independent, modern C++ client for Firebase services.

*Cloud services. Native C++. No baggage.*

Ember is one header, `include/ember.hpp`, written in C++23. It speaks to Cloud
Firestore the way Google's own clients do, over gRPC on HTTP/2, but everything
between your program and the TLS library is here in C++:
- HTTP/2 framing and HPACK header compression;
- gRPC's message framing;
- the protocol buffers the Firestore API exchanges, read and written by hand.

Nothing is generated, nothing is downloaded at build time, and nothing needs
Python, CMake or protoc. A machine with g++ and a TLS library builds it.

Ember is not affiliated with or endorsed by Google. Firebase and Cloud Firestore are
trademarks of Google LLC.

## What it does today

Listen to a document, and be told each time it changes, live:

```cpp
#include "ember.hpp"

int main() {
	auto options = ember::options::for_project("my-project");
	ember::listener listener(options, "rooms/lobby", [](const ember::snapshot& s) {
		std::puts(ember::to_json(s).c_str());
	});
	listener.run();  // until listener.stop()
}
```

It follows Firestore's watch protocol:
- a target for each listen;
- a snapshot only at the moments the server says are consistent;
- the server's resume token kept, so after a dropped connection it reconnects with a
  growing wait and picks up where it left off, telling each change once and none
  twice.

With `FIRESTORE_EMULATOR_HOST` set, it talks to the Firestore emulator instead.

This is an early spike. Still to come: signing in (Firebase Auth), one-off reads,
several listeners sharing one connection, and token refresh.

## Building

TLS comes from [Botan 3](https://botan.randombit.net/) by default:

```sh
g++ -std=c++23 -Iinclude examples/listen.cpp -o build/listen $(pkg-config --cflags --libs botan-3)
```

Or from OpenSSL, with `EMBER_TLS_OPENSSL` defined:

```sh
g++ -std=c++23 -DEMBER_TLS_OPENSSL -Iinclude examples/listen.cpp -o build/listen -lssl -lcrypto
```

## Trying it

```sh
build/listen my-project rooms/lobby                                   # Firestore itself
FIRESTORE_EMULATOR_HOST=localhost:8080 build/listen demo-project rooms/lobby
tests/emulator.sh                                                     # the emulator checks
```

`tests/emulator.sh` listens to a document on the emulator and checks five things:
- the first snapshot;
- a change;
- a change made while the connection was cut, told once after it's back;
- a cut with nothing changed, which tells nothing;
- a delete.

## License

Apache License 2.0. See [LICENSE](LICENSE).
