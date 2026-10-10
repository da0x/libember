// Copyright 2026 Daher Alfawares
// SPDX-License-Identifier: Apache-2.0

// Listens to Firestore documents and prints each as a JSON line each time it changes,
// the first time included. What the client does, like reconnecting, goes to standard
// error. A listen that's refused prints {"path":…,"error":code,"message":…}; the
// program ends once nothing is listened to any more.
//
//     listen PROJECT DOCUMENT_PATH...
//
// With FIRESTORE_EMULATOR_HOST set, it listens to the emulator. With
// EMBER_CUSTOM_TOKEN set, it signs in with that custom token first (Auth's emulator
// when FIREBASE_AUTH_EMULATOR_HOST is set), and EMBER_API_KEY names the web API key.

#include <atomic>
#include <csignal>
#include <iostream>

#include "ember.hpp"

namespace {
    std::atomic<bool> stopping = false;
    void stop(int) { stopping = true; }
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: listen PROJECT DOCUMENT_PATH...\n";
        return 2;
    }
    auto options = ember::options::for_project(argv[1]);
    if (const char* key = std::getenv("EMBER_API_KEY"); key && *key) options.api_key = key;
    options.log = [](std::string_view text) { std::cerr << "ember: " << text << std::endl; };

    ember::auth auth(options);
    if (const char* token = std::getenv("EMBER_CUSTOM_TOKEN"); token && *token) {
        try {
            auth.sign_in_with_custom_token(token);
        } catch (const ember::failure& e) {
            std::cerr << "ember: " << e.what() << std::endl;
            return 1;
        }
        std::cerr << "ember: signed in as " << auth.current_user()->uid << std::endl;
    }

    // Callbacks run here, on the main thread, as the queue is drained.
    ember::queue_executor main_thread;
    ember::database db(options, &auth, &main_thread);
    std::vector<ember::database::registration> listening;
    int open = argc - 2;
    for (int i = 2; i < argc; ++i) {
        std::string path = argv[i];
        listening.push_back(db.listen(
            path, [](const ember::snapshot& s) { std::cout << ember::to_json(s) << std::endl; },
            [path, &open](const ember::error& e) {
                std::cout << "{\"path\":" << ember::to_json(ember::value(path)) << ",\"error\":" << e.code
                          << ",\"message\":" << ember::to_json(ember::value(e.message)) << "}" << std::endl;
                --open;
            }));
    }
    std::signal(SIGINT, stop);
    std::signal(SIGTERM, stop);
    while (!stopping && open > 0) main_thread.run_one_for(std::chrono::milliseconds(100));
    return open > 0 ? 0 : 1;
}
