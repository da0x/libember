// Copyright 2026 Daher Alfawares
// SPDX-License-Identifier: Apache-2.0

// Listens to one Firestore document and prints it as a JSON line each time it
// changes, the first time included. What the client does, like reconnecting, goes to
// standard error.
//
//     listen PROJECT DOCUMENT_PATH
//
// With FIRESTORE_EMULATOR_HOST set, it listens to the emulator. With EMBER_TOKEN set,
// it sends that as the bearer token, like a Firebase ID token.

#include <csignal>
#include <iostream>

#include "ember.hpp"

namespace {
    ember::listener* running = nullptr;
    void stop(int) {
        if (running) running->stop();
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: listen PROJECT DOCUMENT_PATH\n";
        return 2;
    }
    auto options = ember::options::for_project(argv[1]);
    if (const char* token = std::getenv("EMBER_TOKEN"); token && *token) {
        std::string bearer = token;
        options.token = [bearer] { return bearer; };
    }
    options.log = [](std::string_view text) { std::cerr << "ember: " << text << std::endl; };

    ember::listener listener(options, argv[2], [](const ember::snapshot& s) {
        std::cout << ember::to_json(s) << std::endl;
    });
    running = &listener;
    std::signal(SIGINT, stop);
    std::signal(SIGTERM, stop);
    try {
        listener.run();
    } catch (const ember::error& e) {
        std::cerr << "ember: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
