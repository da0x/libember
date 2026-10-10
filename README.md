# Ember

**libember**: an independent, modern C++ client for Firebase services.

*Cloud services. Native C++. No baggage.*

Ember is one header, `include/ember.hpp`, written in C++23. It speaks to Cloud
Firestore the way Google's own clients do, over gRPC on HTTP/2, and to Firebase Auth
over REST. Everything between your program and the TLS library is here in C++:
- HTTP/2 framing and HPACK header compression;
- gRPC's message framing;
- the protocol buffers the Firestore API exchanges, read and written by hand;
- HTTP/1.1 and JSON, for REST.

Nothing is generated, nothing is downloaded at build time, and nothing needs Python,
CMake or protoc. A machine with g++ and a TLS library builds it.

Ember is not affiliated with or endorsed by Google. Firebase and Cloud Firestore are
trademarks of Google LLC.

Version 0.1.0 (`EMBER_VERSION`).

## Building

TLS comes from [Botan 3](https://botan.randombit.net/) by default:

```sh
g++ -std=c++23 -Iinclude program.cpp $(pkg-config --cflags --libs botan-3)
```

Or from OpenSSL, with `EMBER_TLS_OPENSSL` defined:

```sh
g++ -std=c++23 -DEMBER_TLS_OPENSSL -Iinclude program.cpp -lssl -lcrypto
```

## Signing in

```cpp
ember::options options = ember::options::for_project("my-project");
options.api_key = "AIza…";  // the project's web API key

ember::auth auth(options);
auth.sign_in_with_custom_token(token);                 // as a backend made it
auth.sign_in_with_idp("github.com", access_token);     // a provider's access token
auth.sign_in_with_refresh_token(saved);                // signed in before

auth.current_user();    // its uid, and every claim its ID token holds
auth.id_token();        // good for 5 more minutes at least; refreshed when it wouldn't be
auth.refresh_token();   // to keep, and sign in with again later
auth.sign_out();
```

A refused sign-in throws `ember::failure`, with Auth's HTTP status in `status`.

## Reading, once and live

```cpp
ember::queue_executor main_thread;  // callbacks run where this is drained
ember::database db(options, &auth, &main_thread);

ember::snapshot s = db.get("rooms/lobby");
if (s.exists) std::puts(s.data["topic"].as_string().c_str());

auto listening = db.listen("rooms/lobby",
    [](const ember::snapshot& s) { std::puts(ember::to_json(s).c_str()); },
    [](const ember::error& e) { std::printf("can't listen: %d %s\n", e.code, e.message.c_str()); });

for (;;) main_thread.run_one_for(std::chrono::milliseconds(100));
// listening.remove(), or letting it go, stops it.
```

Without an executor, callbacks run on a thread of the database's own. Without `auth`,
nobody is signed in (or the emulator's owner, when it's the emulator).

A `snapshot` has the document's `path`, whether it `exists`, its fields in `data`, and
`from_cache` when it's told from what's known while the connection is down. A
`value` is null, a boolean, an integer, a double, a time, a string, bytes, a reference,
a point, an array or a map:
- `is_null()`, `is_bool()`, `is_integer()`, `is_double()`, `is_string()`, `is_time()`,
  `is_array()` and `is_map()` say which;
- `as_bool()`, `as_integer()`, `as_double()`, `as_string()`, `as_time()`,
  `as_array()` and `as_map()` read it;
- `value["field"]` reads a field of a map, and is null when there's none.

`to_json` writes any of them as JSON, and `parse_json` reads JSON into a `value`.

## How listening behaves

As Google's own clients behave:
- **Snapshots:** the first is told once the server has said all there is, then one for
  each change. A document that isn't there is told as not existing.
- **One stream:** every listen shares it, with a target each. A document listened to
  twice is one target, told to both, and a new listener of a document already known is
  told it at once.
- **Dropped connections:** the stream is reopened with a growing wait and some jitter.
  Each target resumes from the server's resume token, so no change is missed and none
  is told twice.
- **Expiring sign-ins:** the ID token is renewed before it runs out, and the stream is
  reopened with it, resuming.
- **When access ends:** a listener whose document may no longer be read is told
  `error{7, …}` (permission denied) once, then nothing more. Every other listener goes
  on.
- **The watch protocol:** a target the server resets is told again from what it says
  next, and a target whose existence filter disagrees is listened to afresh.
- **Callbacks:** they run only on the executor.

## REST

`ember::https_post(url, headers, body)` and `ember::https_get(url, headers)` make an
HTTP/1.1 call over the same TLS (or plain, for `http://`). Every status comes back in
`response{status, body}`; only a connection that fails throws.

## Emulators

`FIRESTORE_EMULATOR_HOST` and `FIREBASE_AUTH_EMULATOR_HOST` are honored, or
`options.firestore_host` and `options.auth_host` name them. An emulator is spoken to in
plain HTTP/2 or HTTP.

## Not here

Queries, writes, transactions, offline persistence, and Firebase's other products.

## Checks

```sh
tests/run.sh
```

Against the emulators (Firestore on localhost:8080, Auth on localhost:9099):
- **`tests/test.cpp`:**
  - JSON;
  - signing in with a custom token and a refresh token;
  - `get`;
  - one stream for several listeners;
  - callbacks on the executor;
  - permission denied told once while another document goes on;
  - a document made and deleted.
- **`tests/emulator.sh`:** a connection cut through a proxy, with a change made while
  it's down told once after it's back, and nothing told for a cut with no change.
- **`tests/parity/parity.mjs`:** the same document listened to with Google's Firebase
  JS SDK and with Ember at once, through a series of changes. Both must be told the
  same snapshots in the same order. The SDK is a test-only dependency, installed into
  `tests/parity`.

## License

Apache License 2.0. See [LICENSE](LICENSE).
