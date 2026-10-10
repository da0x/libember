// Copyright 2026 Daher Alfawares
// SPDX-License-Identifier: Apache-2.0

// Ember's checks: JSON on its own, then Auth, reads and listens against the Firebase
// emulators (Firestore on localhost:8080, Auth on localhost:9099), in project
// demo-ember. Each check prints ok or FAIL; the program fails if any does.
//
//     g++ -std=c++23 -Iinclude tests/test.cpp -o build/test $(pkg-config --cflags --libs botan-3)

#include <iostream>
#include <set>

#include "ember.hpp"

namespace {

    int failures = 0;

    void check(bool ok, const std::string& what) {
        std::cout << (ok ? "ok: " : "FAIL: ") << what << std::endl;
        if (!ok) ++failures;
    }

    const std::string project = "demo-ember";

    std::string emulator() {
        const char* host = std::getenv("FIRESTORE_EMULATOR_HOST");
        return host && *host ? host : "localhost:8080";
    }

    std::string documents() { return "http://" + emulator() + "/v1/projects/" + project + "/databases/(default)/documents/"; }

    // Writes a document as the emulator's owner, past the rules.
    void write(const std::string& path, const std::string& fields) {
        auto r = ember::https_post(documents() + path + "?currentDocument.exists=false", {{"Authorization", "Bearer owner"}},
                                   "{\"fields\":" + fields + "}");
        if (r.status == 400 || r.status == 409 || r.status == 412) {
            // There already: replace it.
            std::string body = "{\"fields\":" + fields + "}";
            r = ember::detail::http_exchange("PATCH", documents() + path, {{"Authorization", "Bearer owner"}, {"Content-Type", "application/json"}}, &body);
        }
        if (r.status != 200) throw std::runtime_error("writing " + path + ": " + std::to_string(r.status) + " " + r.body);
    }

    void erase(const std::string& path) {
        auto r = ember::detail::http_exchange("DELETE", documents() + path, {{"Authorization", "Bearer owner"}}, nullptr);
        if (r.status != 200) throw std::runtime_error("deleting " + path + ": " + std::to_string(r.status));
    }

    // Only someone a document names in readers may read it.
    void load_rules() {
        std::string rules =
            "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} {"
            " allow read: if request.auth != null && (resource == null || request.auth.uid in resource.data.readers); allow write: if false; } } }";
        std::string body = "{\"rules\":{\"files\":[{\"content\":" + ember::to_json(ember::value(rules)) + "}]}}";
        auto r = ember::detail::http_exchange("PUT", "http://" + emulator() + "/emulator/v1/projects/" + project + ":securityRules",
                                              {{"Content-Type", "application/json"}}, &body);
        if (r.status != 200) throw std::runtime_error("loading rules: " + std::to_string(r.status) + " " + r.body);
    }

    std::string base64url(std::string_view data) {
        std::string out = ember::detail::base64(data);
        for (char& c : out) {
            if (c == '+') c = '-';
            if (c == '/') c = '_';
        }
        while (!out.empty() && out.back() == '=') out.pop_back();
        return out;
    }

    // A custom token the Auth emulator takes, unsigned.
    std::string custom_token(const std::string& uid) {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        std::string payload = "{\"iss\":\"x\",\"sub\":\"x\",\"aud\":\"https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit\","
                              "\"uid\":\"" + uid + "\",\"claims\":{\"service\":true},\"iat\":" + std::to_string(now) +
                              ",\"exp\":" + std::to_string(now + 3600) + "}";
        return base64url("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + base64url(payload) + ".";
    }

    // Drains the queue until `done` holds or `seconds` pass.
    template <typename Done>
    bool until(ember::queue_executor& q, Done done, int seconds = 10) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
        while (!done()) {
            if (std::chrono::steady_clock::now() > deadline) return false;
            q.run_one_for(std::chrono::milliseconds(50));
        }
        return true;
    }

    void json() {
        auto v = ember::parse_json(R"({"a":1,"b":[true,null,2.5],"c":"xé😀\n","d":{"e":-7}})");
        check(v.is_map() && v["a"].is_integer() && v["a"].as_integer() == 1, "JSON: a whole number is an integer");
        check(v["b"].as_array().size() == 3 && v["b"].as_array()[0].as_bool() && v["b"].as_array()[1].is_null() && v["b"].as_array()[2].as_double() == 2.5,
              "JSON: an array keeps its values and their kinds");
        check(v["c"].as_string() == "x\xc3\xa9\xf0\x9f\x98\x80\n", "JSON: escapes, a character past 65535 included, are read as UTF-8");
        check(v["d"]["e"].as_integer() == -7 && v["missing"]["deeper"].is_null() && v["a"]["not a map"].is_null(), "JSON: a field that isn't there is null");
        check(ember::to_json(ember::parse_json(ember::to_json(v))) == ember::to_json(v), "JSON: what's written reads back the same");
        bool refused = false;
        try {
            ember::parse_json("{\"a\":");
        } catch (const ember::failure& e) {
            refused = e.status == 0;
        }
        check(refused, "JSON: what isn't JSON is refused");
        ember::value made(std::map<std::string, ember::value>{{"n", 3}, {"s", "t"}, {"l", std::vector<ember::value>{true, 1.5}}});
        check(ember::to_json(made) == R"({"l":[true,1.5],"n":3,"s":"t"})", "a value can be made, and its map is sorted");
    }

    void signing_in() {
        auto options = ember::options::for_project(project);
        ember::auth auth(options);
        check(!auth.current_user() && auth.id_token().empty(), "nobody is signed in at first");
        auth.sign_in_with_custom_token(custom_token("svc-1"));
        auto user = auth.current_user();
        check(user && user->uid == "svc-1", "a custom token signs in as its uid");
        check(user && user->claims.contains("service") && user->claims.at("service").as_bool(), "the custom token's own claims are the user's");
        std::string first = auth.id_token();
        check(!first.empty() && !auth.refresh_token().empty(), "signed in, there's an ID token and a refresh token");
        check(auth.expires_at() > std::chrono::system_clock::now() + std::chrono::minutes(50), "the ID token lasts about an hour");

        ember::auth again(options);
        again.sign_in_with_refresh_token(auth.refresh_token());
        check(again.current_user() && again.current_user()->uid == "svc-1", "a refresh token signs the same user in again");

        bool refused = false;
        try {
            again.sign_in_with_custom_token("not a token");
        } catch (const ember::failure& e) {
            refused = e.status == 400;
        }
        check(refused, "a bad custom token is refused, with Auth's status");
        auth.sign_out();
        check(!auth.current_user() && auth.id_token().empty(), "signed out, there's no token");
    }

    void reading() {
        write("checks/read", R"({"title":{"stringValue":"read me"},"n":{"integerValue":"7"},"readers":{"arrayValue":{"values":[{"stringValue":"svc-1"}]}}})");
        auto options = ember::options::for_project(project);
        ember::auth auth(options);
        auth.sign_in_with_custom_token(custom_token("svc-1"));
        ember::database db(options, &auth);
        auto s = db.get("checks/read");
        check(s.exists && s.data["title"].as_string() == "read me" && s.data["n"].as_integer() == 7, "get reads a document once");
        auto missing = db.get("checks/nothing-here");
        check(!missing.exists && missing.path == "checks/nothing-here", "get of a missing document says it doesn't exist");
    }

    void listening() {
        write("checks/one", R"({"n":{"integerValue":"1"},"readers":{"arrayValue":{"values":[{"stringValue":"svc-1"}]}}})");
        write("checks/two", R"({"n":{"integerValue":"1"},"readers":{"arrayValue":{"values":[{"stringValue":"svc-1"}]}}})");
        auto options = ember::options::for_project(project);
        std::vector<std::string> said;
        options.log = [&said](std::string_view text) { said.emplace_back(text); };
        ember::auth auth(options);
        auth.sign_in_with_custom_token(custom_token("svc-1"));
        ember::queue_executor here;
        ember::database db(options, &auth, &here);
        auto main_thread = std::this_thread::get_id();

        std::vector<std::int64_t> first, second, other;
        std::vector<ember::error> errors;
        bool on_this_thread = true;
        auto a = db.listen("checks/one", [&](const ember::snapshot& s) {
            on_this_thread = on_this_thread && std::this_thread::get_id() == main_thread;
            first.push_back(s.exists ? s.data["n"].as_integer() : -1);
        }, [&](const ember::error& e) { errors.push_back(e); });
        auto b = db.listen("checks/two", [&](const ember::snapshot& s) { other.push_back(s.data["n"].as_integer()); });
        check(until(here, [&] { return first.size() == 1 && other.size() == 1; }), "the first snapshot of each document is told");
        check(on_this_thread, "callbacks run on the executor's thread");

        // The same document again: told at once, from what's known, and it's still one target.
        auto c = db.listen("checks/one", [&](const ember::snapshot& s) { second.push_back(s.data["n"].as_integer()); });
        check(until(here, [&] { return second.size() == 1; }), "a document listened to twice is told to the second listener at once");
        write("checks/one", R"({"n":{"integerValue":"2"},"readers":{"arrayValue":{"values":[{"stringValue":"svc-1"}]}}})");
        check(until(here, [&] { return first.size() == 2 && second.size() == 2; }) && first.back() == 2 && second.back() == 2,
              "a change is told to both listeners of the document");
        auto streams = std::count(said.begin(), said.end(), "listening");
        auto asked = std::count_if(said.begin(), said.end(), [](const std::string& s) { return s.starts_with("listening to "); });
        check(streams == 1 && asked == 2, "two documents, three listeners: one stream, a target each (" + std::to_string(streams) + " streams, " +
                                              std::to_string(asked) + " targets)");

        // Taken off readers: the listener is told it's denied, once, and nothing more.
        c.remove();
        write("checks/one", R"({"n":{"integerValue":"3"},"readers":{"arrayValue":{"values":[]}}})");
        check(until(here, [&] { return errors.size() == 1; }) && errors[0].code == 7, "a listener that may no longer read is told permission denied");
        write("checks/two", R"({"n":{"integerValue":"2"},"readers":{"arrayValue":{"values":[{"stringValue":"svc-1"}]}}})");
        check(until(here, [&] { return other.size() == 2; }) && other.back() == 2, "another document on the same stream goes on");
        until(here, [] { return false; }, 1);
        check(errors.size() == 1 && second.size() == 2, "the denied listener is told once, and a removed one nothing more");

        // A document that isn't there, then is, then isn't.
        std::vector<bool> exists;
        auto d = db.listen("checks/later", [&](const ember::snapshot& s) { exists.push_back(s.exists); });
        check(until(here, [&] { return exists.size() == 1; }) && !exists[0], "a missing document is told as not existing");
        // Readable only once it exists and names svc-1; the rules let a missing one be
        // listened to, since resource is null and nothing is read.
        write("checks/later", R"({"readers":{"arrayValue":{"values":[{"stringValue":"svc-1"}]}}})");
        check(until(here, [&] { return exists.size() == 2; }) && exists.back(), "and then as existing once it's made");
        erase("checks/later");
        check(until(here, [&] { return exists.size() == 3; }) && !exists.back(), "and as not existing once it's deleted");
    }

}  // namespace

int main() {
    // The emulators, unless the environment names others: never Google's own.
    setenv("FIRESTORE_EMULATOR_HOST", "localhost:8080", 0);
    setenv("FIREBASE_AUTH_EMULATOR_HOST", "localhost:9099", 0);
    json();
    try {
        load_rules();
        signing_in();
        reading();
        listening();
    } catch (const std::exception& e) {
        check(false, std::string("no exception: ") + e.what());
    }
    std::cout << (failures ? std::to_string(failures) + " failed" : "all passed") << std::endl;
    return failures ? 1 : 0;
}
