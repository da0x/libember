// Copyright 2026 Daher Alfawares
// SPDX-License-Identifier: Apache-2.0

// Ember: an independent, modern C++ client for Firebase services, in one header.
//
// It speaks to Cloud Firestore the way Google's own clients do, over gRPC on HTTP/2,
// but everything between the program and the TLS library is written here in C++:
// HTTP/2 framing and HPACK, gRPC's message framing, and the protocol buffers the
// Firestore API exchanges, encoded and decoded by hand. Nothing is generated, nothing
// is downloaded at build time, and a machine with g++ and a TLS library builds it:
//
//     g++ -std=c++23 program.cpp $(pkg-config --cflags --libs botan-3)
//
// TLS comes from Botan 3 by default. Define EMBER_TLS_OPENSSL before including this
// header to use OpenSSL instead (and link -lssl -lcrypto).
//
// What it does: sign in with Firebase Auth (a custom token, a provider's access
// token, or a refresh token) and keep the ID token fresh; read a document once; and
// listen to documents, told live each time one changes, as Google's own clients are.
// Every listen shares one stream, a target each; a dropped connection resumes each
// from the server's resume token, so no change is missed and none is told twice; a
// snapshot is told only at the points the server says are consistent; and callbacks
// run on an executor the program chooses. It also makes plain HTTPS calls, for REST.
//
// It doesn't query, write, or keep anything offline.
//
// Not affiliated with or endorsed by Google. Firebase and Cloud Firestore are
// trademarks of Google LLC.

#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef EMBER_TLS_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#else
#include <botan/auto_rng.h>
#include <botan/certstor_system.h>
#include <botan/credentials_manager.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_session_manager_memory.h>
#endif

namespace ember {

#define EMBER_VERSION "0.1.1"

    // Anything that went wrong: a connection, the protocol, or the server saying no.
    // status is the HTTP status when a REST call was refused, and 0 otherwise.
    struct failure : std::runtime_error {
        int status = 0;
        using std::runtime_error::runtime_error;
        failure(int status, const std::string& message) : std::runtime_error(message), status(status) {}
    };

    // The connection itself failed: worth trying again.
    struct connection_error : failure {
        using failure::failure;
    };

    // The server refused, with a gRPC status, like 7 for permission denied.
    struct status_error : failure {
        status_error(int code, const std::string& message)
            : failure(message.empty() ? "gRPC status " + std::to_string(code) : message), code(code) {}
        int code;
    };

    // What a listener is told when its document can't be listened to any more: a gRPC
    // status, like 7 for permission denied, and the server's words.
    struct error {
        int code = 0;
        std::string message;
    };

    // ---------------------------------------------------------------------------
    // Values, as Firestore stores them
    // ---------------------------------------------------------------------------

    struct timestamp {
        std::int64_t seconds = 0;
        std::int32_t nanos = 0;
        friend bool operator==(const timestamp&, const timestamp&) = default;
    };

    struct geo_point {
        double latitude = 0;
        double longitude = 0;
    };

    // One field's value. A map keeps its fields sorted by name, so two equal documents
    // print the same.
    class value {
    public:
        enum class kind { null, boolean, integer, floating, time, string, bytes, reference, point, array, map };

        kind type = kind::null;
        bool boolean = false;
        std::int64_t integer = 0;
        double floating = 0;
        ember::timestamp time;
        std::string text;  // a string, bytes or a reference
        geo_point point;
        std::vector<value> items;
        std::map<std::string, value> fields;

        value() = default;
        value(bool b) : type(kind::boolean), boolean(b) {}
        value(int n) : type(kind::integer), integer(n) {}
        value(long n) : type(kind::integer), integer(n) {}
        value(long long n) : type(kind::integer), integer(n) {}
        value(double n) : type(kind::floating), floating(n) {}
        value(const char* s) : type(kind::string), text(s) {}
        value(std::string s) : type(kind::string), text(std::move(s)) {}
        value(std::vector<value> list) : type(kind::array), items(std::move(list)) {}
        value(std::map<std::string, value> map) : type(kind::map), fields(std::move(map)) {}

        bool is_null() const { return type == kind::null; }
        bool is_bool() const { return type == kind::boolean; }
        bool is_integer() const { return type == kind::integer; }
        bool is_double() const { return type == kind::floating; }
        bool is_string() const { return type == kind::string; }
        bool is_time() const { return type == kind::time; }
        bool is_array() const { return type == kind::array; }
        bool is_map() const { return type == kind::map; }
        bool as_bool() const { return type == kind::boolean && boolean; }
        // An integer, or a floating-point number cut to one; 0 for anything else.
        std::int64_t as_integer() const {
            if (type == kind::integer) return integer;
            if (type == kind::floating) return static_cast<std::int64_t>(floating);
            return 0;
        }
        double as_double() const {
            if (type == kind::floating) return floating;
            if (type == kind::integer) return static_cast<double>(integer);
            return 0;
        }
        // A string, a reference's path, or bytes; empty for anything else.
        const std::string& as_string() const {
            static const std::string none;
            return type == kind::string || type == kind::reference || type == kind::bytes ? text : none;
        }
        const std::vector<value>& as_array() const {
            static const std::vector<value> none;
            return type == kind::array ? items : none;
        }
        const std::map<std::string, value>& as_map() const {
            static const std::map<std::string, value> none;
            return type == kind::map ? fields : none;
        }
        // A field of a map, or null when it has none of that name.
        const value& operator[](std::string_view name) const {
            static const value none;
            const value* found = find(name);
            return found ? *found : none;
        }
        const value* find(std::string_view name) const {
            if (type != kind::map) return nullptr;
            auto it = fields.find(std::string(name));
            return it == fields.end() ? nullptr : &it->second;
        }
        std::chrono::sys_time<std::chrono::nanoseconds> as_time() const {
            if (type != kind::time) return {};
            return std::chrono::sys_time<std::chrono::nanoseconds>(std::chrono::seconds(time.seconds) + std::chrono::nanoseconds(time.nanos));
        }

        static value map() {
            value v;
            v.type = kind::map;
            return v;
        }
        static value of(std::string text) {
            value v;
            v.type = kind::string;
            v.text = std::move(text);
            return v;
        }
    };

    namespace detail {

        inline void append_escaped(std::string& out, std::string_view text) {
            out += '"';
            for (unsigned char c : text) {
                switch (c) {
                    case '"': out += "\\\""; break;
                    case '\\': out += "\\\\"; break;
                    case '\n': out += "\\n"; break;
                    case '\r': out += "\\r"; break;
                    case '\t': out += "\\t"; break;
                    case '\b': out += "\\b"; break;
                    case '\f': out += "\\f"; break;
                    default:
                        if (c < 0x20) {
                            char hex[8];
                            std::snprintf(hex, sizeof hex, "\\u%04x", c);
                            out += hex;
                        } else {
                            out += static_cast<char>(c);
                        }
                }
            }
            out += '"';
        }

        inline std::string base64(std::string_view data) {
            static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            std::size_t i = 0;
            for (; i + 2 < data.size(); i += 3) {
                std::uint32_t n = (std::uint8_t(data[i]) << 16) | (std::uint8_t(data[i + 1]) << 8) | std::uint8_t(data[i + 2]);
                out += alphabet[(n >> 18) & 63];
                out += alphabet[(n >> 12) & 63];
                out += alphabet[(n >> 6) & 63];
                out += alphabet[n & 63];
            }
            if (i + 1 == data.size()) {
                std::uint32_t n = std::uint8_t(data[i]) << 16;
                out += alphabet[(n >> 18) & 63];
                out += alphabet[(n >> 12) & 63];
                out += "==";
            } else if (i + 2 == data.size()) {
                std::uint32_t n = (std::uint8_t(data[i]) << 16) | (std::uint8_t(data[i + 1]) << 8);
                out += alphabet[(n >> 18) & 63];
                out += alphabet[(n >> 12) & 63];
                out += alphabet[(n >> 6) & 63];
                out += '=';
            }
            return out;
        }

    }  // namespace detail

    // A time as RFC 3339, in UTC, as Firestore writes it: 2026-10-10T06:30:00.123456Z.
    inline std::string to_string(const timestamp& t) {
        std::time_t seconds = static_cast<std::time_t>(t.seconds);
        std::tm parts{};
        gmtime_r(&seconds, &parts);
        char text[64];
        std::size_t length = std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%S", &parts);
        std::string out(text, length);
        if (t.nanos != 0) {
            char fraction[16];
            std::snprintf(fraction, sizeof fraction, ".%09d", t.nanos);
            std::string digits = fraction;
            while (digits.back() == '0') digits.pop_back();
            out += digits;
        }
        return out + "Z";
    }

    // A value as JSON: numbers as numbers, times as RFC 3339 strings, bytes as base64,
    // a reference as its path, and a point as {"latitude", "longitude"}.
    inline void to_json(const value& v, std::string& out) {
        switch (v.type) {
            case value::kind::null: out += "null"; break;
            case value::kind::boolean: out += v.boolean ? "true" : "false"; break;
            case value::kind::integer: out += std::to_string(v.integer); break;
            case value::kind::floating: {
                char number[40];
                std::snprintf(number, sizeof number, "%.17g", v.floating);
                out += number;
                break;
            }
            case value::kind::time: detail::append_escaped(out, to_string(v.time)); break;
            case value::kind::string: detail::append_escaped(out, v.text); break;
            case value::kind::bytes: detail::append_escaped(out, detail::base64(v.text)); break;
            case value::kind::reference: detail::append_escaped(out, v.text); break;
            case value::kind::point: {
                char point[96];
                std::snprintf(point, sizeof point, "{\"latitude\":%.17g,\"longitude\":%.17g}", v.point.latitude, v.point.longitude);
                out += point;
                break;
            }
            case value::kind::array: {
                out += '[';
                for (std::size_t i = 0; i < v.items.size(); ++i) {
                    if (i) out += ',';
                    to_json(v.items[i], out);
                }
                out += ']';
                break;
            }
            case value::kind::map: {
                out += '{';
                bool first = true;
                for (const auto& [name, field] : v.fields) {
                    if (!first) out += ',';
                    first = false;
                    detail::append_escaped(out, name);
                    out += ':';
                    to_json(field, out);
                }
                out += '}';
                break;
            }
        }
    }

    inline std::string to_json(const value& v) {
        std::string out;
        to_json(v, out);
        return out;
    }

    // ---------------------------------------------------------------------------
    // Protocol buffers' wire format, by hand
    // ---------------------------------------------------------------------------
    //
    // Only what the Firestore messages here need: varints, 64-bit numbers, and
    // length-delimited fields (strings, bytes and nested messages). Field numbers are
    // the ones in google/firestore/v1's .proto files, named where they're used.

    namespace protobuf {

        enum wire : int { varint_wire = 0, fixed64_wire = 1, length_wire = 2, fixed32_wire = 5 };

        class writer {
        public:
            void varint(std::uint64_t n) {
                while (n >= 0x80) {
                    out_ += static_cast<char>((n & 0x7f) | 0x80);
                    n >>= 7;
                }
                out_ += static_cast<char>(n);
            }
            void tag(int field, wire type) { varint((static_cast<std::uint64_t>(field) << 3) | type); }
            void integer(int field, std::int64_t n) {
                tag(field, varint_wire);
                varint(static_cast<std::uint64_t>(n));
            }
            void bytes(int field, std::string_view data) {
                tag(field, length_wire);
                varint(data.size());
                out_ += data;
            }
            void message(int field, const writer& inner) { bytes(field, inner.out_); }
            const std::string& data() const { return out_; }

        private:
            std::string out_;
        };

        class reader {
        public:
            explicit reader(std::string_view data) : data_(data) {}

            // The next field's number and wire type, or false at the end.
            bool next(int& field, wire& type) {
                if (at_ >= data_.size()) return false;
                std::uint64_t key = varint();
                field = static_cast<int>(key >> 3);
                type = static_cast<wire>(key & 7);
                return true;
            }
            std::uint64_t varint() {
                std::uint64_t n = 0;
                for (int shift = 0; shift < 64; shift += 7) {
                    if (at_ >= data_.size()) throw failure("a protocol buffer ends inside a number");
                    auto byte = static_cast<std::uint8_t>(data_[at_++]);
                    n |= static_cast<std::uint64_t>(byte & 0x7f) << shift;
                    if (!(byte & 0x80)) return n;
                }
                throw failure("a protocol buffer number is too long");
            }
            std::string_view bytes() {
                std::uint64_t length = varint();
                if (length > data_.size() - at_) throw failure("a protocol buffer field runs past its end");
                std::string_view out = data_.substr(at_, length);
                at_ += length;
                return out;
            }
            double floating() {
                std::uint64_t bits = fixed(8);
                double out;
                std::memcpy(&out, &bits, sizeof out);
                return out;
            }
            // A repeated int32, which may be packed into one field or written one a field.
            void integers(wire type, std::vector<std::int32_t>& out) {
                if (type == length_wire) {
                    reader packed(bytes());
                    while (packed.at_ < packed.data_.size()) out.push_back(static_cast<std::int32_t>(packed.varint()));
                } else {
                    out.push_back(static_cast<std::int32_t>(varint()));
                }
            }
            void skip(wire type) {
                switch (type) {
                    case varint_wire: varint(); break;
                    case fixed64_wire: fixed(8); break;
                    case length_wire: bytes(); break;
                    case fixed32_wire: fixed(4); break;
                    default: throw failure("a protocol buffer field has an unknown wire type");
                }
            }

        private:
            std::uint64_t fixed(std::size_t size) {
                if (size > data_.size() - at_) throw failure("a protocol buffer ends inside a number");
                std::uint64_t n = 0;
                for (std::size_t i = 0; i < size; ++i) n |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(data_[at_ + i])) << (8 * i);
                at_ += size;
                return n;
            }

            std::string_view data_;
            std::size_t at_ = 0;
        };

    }  // namespace protobuf

    // ---------------------------------------------------------------------------
    // HPACK, HTTP/2's header compression (RFC 7541)
    // ---------------------------------------------------------------------------

    namespace hpack {

        // The static table, Appendix A. Index 0 is unused.
        inline constexpr std::pair<std::string_view, std::string_view> static_table[62] = {
            {"", ""},
            {":authority", ""}, {":method", "GET"}, {":method", "POST"}, {":path", "/"},
            {":path", "/index.html"}, {":scheme", "http"}, {":scheme", "https"}, {":status", "200"},
            {":status", "204"}, {":status", "206"}, {":status", "304"}, {":status", "400"},
            {":status", "404"}, {":status", "500"}, {"accept-charset", ""}, {"accept-encoding", "gzip, deflate"},
            {"accept-language", ""}, {"accept-ranges", ""}, {"accept", ""}, {"access-control-allow-origin", ""},
            {"age", ""}, {"allow", ""}, {"authorization", ""}, {"cache-control", ""},
            {"content-disposition", ""}, {"content-encoding", ""}, {"content-language", ""}, {"content-length", ""},
            {"content-location", ""}, {"content-range", ""}, {"content-type", ""}, {"cookie", ""},
            {"date", ""}, {"etag", ""}, {"expect", ""}, {"expires", ""},
            {"from", ""}, {"host", ""}, {"if-match", ""}, {"if-modified-since", ""},
            {"if-none-match", ""}, {"if-range", ""}, {"if-unmodified-since", ""}, {"last-modified", ""},
            {"link", ""}, {"location", ""}, {"max-forwards", ""}, {"proxy-authenticate", ""},
            {"proxy-authorization", ""}, {"range", ""}, {"referer", ""}, {"refresh", ""},
            {"retry-after", ""}, {"server", ""}, {"set-cookie", ""}, {"strict-transport-security", ""},
            {"transfer-encoding", ""}, {"user-agent", ""}, {"vary", ""}, {"via", ""},
            {"www-authenticate", ""},
        };

        struct huffman_code {
            std::uint32_t bits;
            std::uint8_t length;
        };

        // The Huffman code, Appendix B: each byte's code, and 256, the end of the string.
        inline constexpr huffman_code huffman_codes[257] = {
            {0x1ff8, 13}, {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28}, {0xfffffe4, 28}, {0xfffffe5, 28},
            {0xfffffe6, 28}, {0xfffffe7, 28}, {0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30}, {0xfffffe9, 28},
            {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28}, {0xfffffed, 28}, {0xfffffee, 28},
            {0xfffffef, 28}, {0xffffff0, 28}, {0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28},
            {0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28}, {0xffffff8, 28}, {0xffffff9, 28},
            {0xffffffa, 28}, {0xffffffb, 28}, {0x14, 6}, {0x3f8, 10}, {0x3f9, 10}, {0xffa, 12},
            {0x1ff9, 13}, {0x15, 6}, {0xf8, 8}, {0x7fa, 11}, {0x3fa, 10}, {0x3fb, 10},
            {0xf9, 8}, {0x7fb, 11}, {0xfa, 8}, {0x16, 6}, {0x17, 6}, {0x18, 6},
            {0x0, 5}, {0x1, 5}, {0x2, 5}, {0x19, 6}, {0x1a, 6}, {0x1b, 6},
            {0x1c, 6}, {0x1d, 6}, {0x1e, 6}, {0x1f, 6}, {0x5c, 7}, {0xfb, 8},
            {0x7ffc, 15}, {0x20, 6}, {0xffb, 12}, {0x3fc, 10}, {0x1ffa, 13}, {0x21, 6},
            {0x5d, 7}, {0x5e, 7}, {0x5f, 7}, {0x60, 7}, {0x61, 7}, {0x62, 7},
            {0x63, 7}, {0x64, 7}, {0x65, 7}, {0x66, 7}, {0x67, 7}, {0x68, 7},
            {0x69, 7}, {0x6a, 7}, {0x6b, 7}, {0x6c, 7}, {0x6d, 7}, {0x6e, 7},
            {0x6f, 7}, {0x70, 7}, {0x71, 7}, {0x72, 7}, {0xfc, 8}, {0x73, 7},
            {0xfd, 8}, {0x1ffb, 13}, {0x7fff0, 19}, {0x1ffc, 13}, {0x3ffc, 14}, {0x22, 6},
            {0x7ffd, 15}, {0x3, 5}, {0x23, 6}, {0x4, 5}, {0x24, 6}, {0x5, 5},
            {0x25, 6}, {0x26, 6}, {0x27, 6}, {0x6, 5}, {0x74, 7}, {0x75, 7},
            {0x28, 6}, {0x29, 6}, {0x2a, 6}, {0x7, 5}, {0x2b, 6}, {0x76, 7},
            {0x2c, 6}, {0x8, 5}, {0x9, 5}, {0x2d, 6}, {0x77, 7}, {0x78, 7},
            {0x79, 7}, {0x7a, 7}, {0x7b, 7}, {0x7ffe, 15}, {0x7fc, 11}, {0x3ffd, 14},
            {0x1ffd, 13}, {0xffffffc, 28}, {0xfffe6, 20}, {0x3fffd2, 22}, {0xfffe7, 20}, {0xfffe8, 20},
            {0x3fffd3, 22}, {0x3fffd4, 22}, {0x3fffd5, 22}, {0x7fffd9, 23}, {0x3fffd6, 22}, {0x7fffda, 23},
            {0x7fffdb, 23}, {0x7fffdc, 23}, {0x7fffdd, 23}, {0x7fffde, 23}, {0xffffeb, 24}, {0x7fffdf, 23},
            {0xffffec, 24}, {0xffffed, 24}, {0x3fffd7, 22}, {0x7fffe0, 23}, {0xffffee, 24}, {0x7fffe1, 23},
            {0x7fffe2, 23}, {0x7fffe3, 23}, {0x7fffe4, 23}, {0x1fffdc, 21}, {0x3fffd8, 22}, {0x7fffe5, 23},
            {0x3fffd9, 22}, {0x7fffe6, 23}, {0x7fffe7, 23}, {0xffffef, 24}, {0x3fffda, 22}, {0x1fffdd, 21},
            {0xfffe9, 20}, {0x3fffdb, 22}, {0x3fffdc, 22}, {0x7fffe8, 23}, {0x7fffe9, 23}, {0x1fffde, 21},
            {0x7fffea, 23}, {0x3fffdd, 22}, {0x3fffde, 22}, {0xfffff0, 24}, {0x1fffdf, 21}, {0x3fffdf, 22},
            {0x7fffeb, 23}, {0x7fffec, 23}, {0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffe0, 22}, {0x1fffe2, 21},
            {0x7fffed, 23}, {0x3fffe1, 22}, {0x7fffee, 23}, {0x7fffef, 23}, {0xfffea, 20}, {0x3fffe2, 22},
            {0x3fffe3, 22}, {0x3fffe4, 22}, {0x7ffff0, 23}, {0x3fffe5, 22}, {0x3fffe6, 22}, {0x7ffff1, 23},
            {0x3ffffe0, 26}, {0x3ffffe1, 26}, {0xfffeb, 20}, {0x7fff1, 19}, {0x3fffe7, 22}, {0x7ffff2, 23},
            {0x3fffe8, 22}, {0x1ffffec, 25}, {0x3ffffe2, 26}, {0x3ffffe3, 26}, {0x3ffffe4, 26}, {0x7ffffde, 27},
            {0x7ffffdf, 27}, {0x3ffffe5, 26}, {0xfffff1, 24}, {0x1ffffed, 25}, {0x7fff2, 19}, {0x1fffe3, 21},
            {0x3ffffe6, 26}, {0x7ffffe0, 27}, {0x7ffffe1, 27}, {0x3ffffe7, 26}, {0x7ffffe2, 27}, {0xfffff2, 24},
            {0x1fffe4, 21}, {0x1fffe5, 21}, {0x3ffffe8, 26}, {0x3ffffe9, 26}, {0xffffffd, 28}, {0x7ffffe3, 27},
            {0x7ffffe4, 27}, {0x7ffffe5, 27}, {0xfffec, 20}, {0xfffff3, 24}, {0xfffed, 20}, {0x1fffe6, 21},
            {0x3fffe9, 22}, {0x1fffe7, 21}, {0x1fffe8, 21}, {0x7ffff3, 23}, {0x3fffea, 22}, {0x3fffeb, 22},
            {0x1ffffee, 25}, {0x1ffffef, 25}, {0xfffff4, 24}, {0xfffff5, 24}, {0x3ffffea, 26}, {0x7ffff4, 23},
            {0x3ffffeb, 26}, {0x7ffffe6, 27}, {0x3ffffec, 26}, {0x3ffffed, 26}, {0x7ffffe7, 27}, {0x7ffffe8, 27},
            {0x7ffffe9, 27}, {0x7ffffea, 27}, {0x7ffffeb, 27}, {0xffffffe, 28}, {0x7ffffec, 27}, {0x7ffffed, 27},
            {0x7ffffee, 27}, {0x7ffffef, 27}, {0x7fffff0, 27}, {0x3ffffee, 26}, {0x3fffffff, 30},
        };

        // The code as a tree, built once: each node has a child for 0 and for 1, or is a
        // leaf holding a symbol.
        struct huffman_tree {
            struct node {
                std::int16_t child[2] = {-1, -1};
                std::int16_t symbol = -1;
            };
            std::vector<node> nodes;

            huffman_tree() {
                nodes.emplace_back();
                for (int symbol = 0; symbol < 257; ++symbol) {
                    const auto& code = huffman_codes[symbol];
                    std::size_t at = 0;
                    for (int bit = code.length - 1; bit >= 0; --bit) {
                        int direction = (code.bits >> bit) & 1;
                        if (nodes[at].child[direction] < 0) {
                            nodes[at].child[direction] = static_cast<std::int16_t>(nodes.size());
                            nodes.emplace_back();
                        }
                        at = static_cast<std::size_t>(nodes[at].child[direction]);
                    }
                    nodes[at].symbol = static_cast<std::int16_t>(symbol);
                }
            }
        };

        inline std::string huffman_decode(std::string_view in) {
            static const huffman_tree tree;
            std::string out;
            std::size_t at = 0;
            int depth = 0;
            for (unsigned char byte : in) {
                for (int bit = 7; bit >= 0; --bit) {
                    auto next = tree.nodes[at].child[(byte >> bit) & 1];
                    if (next < 0) throw failure("a header has a Huffman code that doesn't exist");
                    at = static_cast<std::size_t>(next);
                    ++depth;
                    if (auto symbol = tree.nodes[at].symbol; symbol >= 0) {
                        if (symbol == 256) throw failure("a header holds Huffman's end-of-string code");
                        out += static_cast<char>(symbol);
                        at = 0;
                        depth = 0;
                    }
                }
            }
            // What's left over is padding: at most seven bits, all ones, which is the
            // start of the end-of-string code.
            if (depth > 7) throw failure("a header's Huffman padding is too long");
            return out;
        }

        inline std::uint64_t read_integer(std::string_view in, std::size_t& at, int prefix) {
            if (at >= in.size()) throw failure("a header block ends early");
            std::uint64_t mask = (1u << prefix) - 1;
            std::uint64_t n = static_cast<std::uint8_t>(in[at++]) & mask;
            if (n < mask) return n;
            for (int shift = 0; shift < 63; shift += 7) {
                if (at >= in.size()) throw failure("a header block ends inside a number");
                auto byte = static_cast<std::uint8_t>(in[at++]);
                n += static_cast<std::uint64_t>(byte & 0x7f) << shift;
                if (!(byte & 0x80)) return n;
            }
            throw failure("a header block's number is too long");
        }

        inline std::string read_string(std::string_view in, std::size_t& at) {
            if (at >= in.size()) throw failure("a header block ends early");
            bool huffman = static_cast<std::uint8_t>(in[at]) & 0x80;
            std::uint64_t length = read_integer(in, at, 7);
            if (length > in.size() - at) throw failure("a header's text runs past the block");
            std::string_view raw = in.substr(at, length);
            at += length;
            return huffman ? huffman_decode(raw) : std::string(raw);
        }

        using header = std::pair<std::string, std::string>;

        // Reads header blocks, keeping the dynamic table the peer's encoder builds.
        class decoder {
        public:
            std::vector<header> decode(std::string_view block) {
                std::vector<header> out;
                std::size_t at = 0;
                while (at < block.size()) {
                    auto first = static_cast<std::uint8_t>(block[at]);
                    if (first & 0x80) {  // indexed
                        out.push_back(entry(read_integer(block, at, 7)));
                    } else if (first & 0x40) {  // literal, added to the table
                        auto h = literal(block, at, 6);
                        add(h);
                        out.push_back(std::move(h));
                    } else if (first & 0x20) {  // the table's size changes
                        std::uint64_t size = read_integer(block, at, 5);
                        if (size > limit_) throw failure("the peer grew the header table past what we allowed");
                        maximum_ = size;
                        evict();
                    } else {  // literal, not indexed or never indexed
                        out.push_back(literal(block, at, 4));
                    }
                }
                return out;
            }

        private:
            header entry(std::uint64_t index) {
                if (index == 0) throw failure("a header names table entry 0");
                if (index < 62) return {std::string(static_table[index].first), std::string(static_table[index].second)};
                std::uint64_t dynamic = index - 62;
                if (dynamic >= table_.size()) throw failure("a header names a table entry that doesn't exist");
                return table_[dynamic];
            }
            header literal(std::string_view block, std::size_t& at, int prefix) {
                std::uint64_t index = read_integer(block, at, prefix);
                std::string name = index ? entry(index).first : read_string(block, at);
                return {std::move(name), read_string(block, at)};
            }
            void add(const header& h) {
                table_.push_front(h);
                size_ += h.first.size() + h.second.size() + 32;
                evict();
            }
            void evict() {
                while (size_ > maximum_ && !table_.empty()) {
                    size_ -= table_.back().first.size() + table_.back().second.size() + 32;
                    table_.pop_back();
                }
            }

            std::deque<header> table_;  // newest first
            std::size_t size_ = 0;
            std::size_t maximum_ = 4096;
            std::size_t limit_ = 4096;  // SETTINGS_HEADER_TABLE_SIZE, which we leave at its default
        };

        inline void write_integer(std::string& out, std::uint64_t n, int prefix, std::uint8_t first) {
            std::uint64_t mask = (1u << prefix) - 1;
            if (n < mask) {
                out += static_cast<char>(first | n);
                return;
            }
            out += static_cast<char>(first | mask);
            n -= mask;
            while (n >= 0x80) {
                out += static_cast<char>((n & 0x7f) | 0x80);
                n >>= 7;
            }
            out += static_cast<char>(n);
        }

        // Writes every header as a literal that isn't indexed, so we keep no table of our
        // own: our requests are few and small, and simple beats a few saved bytes.
        inline std::string encode(const std::vector<header>& headers) {
            std::string out;
            for (const auto& [name, value] : headers) {
                out += '\0';
                write_integer(out, name.size(), 7, 0);
                out += name;
                write_integer(out, value.size(), 7, 0);
                out += value;
            }
            return out;
        }

    }  // namespace hpack

    // ---------------------------------------------------------------------------
    // Transports: a TCP socket, and TLS over it
    // ---------------------------------------------------------------------------
    //
    // A transport moves bytes. HTTP/2 sits on one and doesn't know which it is, so the
    // TLS library is a choice made in one place: Botan unless EMBER_TLS_OPENSSL.

    using milliseconds = std::chrono::milliseconds;

    class transport {
    public:
        virtual ~transport() = default;
        // Reads what's there, up to out's size, waiting at most `wait`. Gives nothing on a
        // timeout and throws connection_error when the peer has closed or the link is gone.
        virtual std::optional<std::size_t> read(std::span<char> out, milliseconds wait) = 0;
        virtual void write(std::string_view data) = 0;
        // The protocol TLS agreed on with ALPN, like "h2", or empty.
        virtual std::string protocol() const { return {}; }
    };

    namespace detail {

        class socket {
        public:
            socket(const std::string& host, const std::string& port) {
                addrinfo hints{};
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;
                addrinfo* found = nullptr;
                if (int failed = getaddrinfo(host.c_str(), port.c_str(), &hints, &found); failed != 0) {
                    throw connection_error("can't find " + host + ": " + gai_strerror(failed));
                }
                for (addrinfo* a = found; a; a = a->ai_next) {
                    int fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
                    if (fd < 0) continue;
                    if (::connect(fd, a->ai_addr, a->ai_addrlen) == 0) {
                        descriptor_ = fd;
                        break;
                    }
                    ::close(fd);
                }
                freeaddrinfo(found);
                if (descriptor_ < 0) throw connection_error("can't connect to " + host + ":" + port);
                // Small frames go at once: a ping's answer shouldn't wait for more to send.
                int on = 1;
                setsockopt(descriptor_, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
            }
            ~socket() {
                if (descriptor_ >= 0) ::close(descriptor_);
            }
            socket(const socket&) = delete;
            socket& operator=(const socket&) = delete;

            int descriptor() const { return descriptor_; }

            bool readable(milliseconds wait) {
                pollfd p{descriptor_, POLLIN, 0};
                int ready = ::poll(&p, 1, static_cast<int>(wait.count()));
                if (ready < 0) {
                    if (errno == EINTR) return false;
                    throw connection_error(std::string("waiting on the connection: ") + std::strerror(errno));
                }
                return ready > 0;
            }
            std::size_t receive(std::span<char> out) {
                for (;;) {
                    ssize_t n = ::recv(descriptor_, out.data(), out.size(), 0);
                    if (n > 0) return static_cast<std::size_t>(n);
                    if (n == 0) throw connection_error("the server closed the connection");
                    if (errno == EINTR) continue;
                    throw connection_error(std::string("reading: ") + std::strerror(errno));
                }
            }
            void send(std::string_view data) {
                while (!data.empty()) {
                    ssize_t n = ::send(descriptor_, data.data(), data.size(), MSG_NOSIGNAL);
                    if (n < 0) {
                        if (errno == EINTR) continue;
                        throw connection_error(std::string("writing: ") + std::strerror(errno));
                    }
                    data.remove_prefix(static_cast<std::size_t>(n));
                }
            }
            // Ends the connection at once, from any thread, so a blocked read returns.
            void shut() { ::shutdown(descriptor_, SHUT_RDWR); }

        private:
            int descriptor_ = -1;
        };

    }  // namespace detail

    // Plain TCP, for the emulators, which speak HTTP/2 without TLS.
    class plain_transport : public transport {
    public:
        plain_transport(const std::string& host, const std::string& port) : socket_(host, port) {}
        std::optional<std::size_t> read(std::span<char> out, milliseconds wait) override {
            if (!socket_.readable(wait)) return std::nullopt;
            return socket_.receive(out);
        }
        void write(std::string_view data) override { socket_.send(data); }

    private:
        detail::socket socket_;
    };

#ifndef EMBER_TLS_OPENSSL

    // TLS by Botan 3, checking the server's certificate against the system's roots.
    class tls_transport : public transport {
    public:
        tls_transport(const std::string& host, const std::string& port, std::vector<std::string> protocols)
            : socket_(host, port) {
            auto random = std::make_shared<Botan::AutoSeeded_RNG>();
            callbacks_ = std::make_shared<callbacks>(*this);
            client_ = std::make_unique<Botan::TLS::Client>(
                callbacks_, std::make_shared<Botan::TLS::Session_Manager_In_Memory>(random),
                std::make_shared<credentials>(), std::make_shared<policy>(), random,
                Botan::TLS::Server_Information(host, static_cast<std::uint16_t>(std::stoi(port))),
                Botan::TLS::Protocol_Version::latest_tls_version(), protocols);
            while (!client_->is_active()) {
                if (client_->is_closed()) throw connection_error("TLS with " + host + " closed before it began");
                feed(milliseconds(30000), true);
            }
        }
        ~tls_transport() override {
            try {
                if (client_ && client_->is_active()) client_->close();
            } catch (...) {
            }
        }

        std::optional<std::size_t> read(std::span<char> out, milliseconds wait) override {
            if (plain_.empty()) {
                if (!feed(wait, false) || plain_.empty()) return std::nullopt;
            }
            std::size_t n = std::min(out.size(), plain_.size());
            std::copy_n(plain_.begin(), n, out.begin());
            plain_.erase(plain_.begin(), plain_.begin() + static_cast<std::ptrdiff_t>(n));
            return n;
        }
        void write(std::string_view data) override {
            client_->send(std::span(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
        }
        std::string protocol() const override { return client_->application_protocol(); }

    private:
        struct callbacks : Botan::TLS::Callbacks {
            explicit callbacks(tls_transport& owner) : owner(owner) {}
            void tls_emit_data(std::span<const std::uint8_t> data) override {
                owner.socket_.send({reinterpret_cast<const char*>(data.data()), data.size()});
            }
            void tls_record_received(std::uint64_t, std::span<const std::uint8_t> data) override {
                owner.plain_.insert(owner.plain_.end(), data.begin(), data.end());
            }
            void tls_alert(Botan::TLS::Alert alert) override {
                if (alert.is_fatal() || alert.type() == Botan::TLS::Alert::CloseNotify) owner.closed_ = true;
            }
            tls_transport& owner;
        };

        // Botan's defaults, except that a certificate without revocation data (no OCSP
        // answer stapled) is accepted, as browsers and OpenSSL accept it; the chain is
        // still checked against the system's roots and the server's name.
        struct policy : Botan::TLS::Policy {
            bool require_cert_revocation_info() const override { return false; }
        };

        struct credentials : Botan::Credentials_Manager {
            std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string&, const std::string&) override {
                return {&roots};
            }
            Botan::System_Certificate_Store roots;
        };

        // Reads what the socket has and gives it to TLS. False on a timeout.
        bool feed(milliseconds wait, bool handshaking) {
            if (closed_) throw connection_error("the server closed the connection");
            if (!socket_.readable(wait)) {
                if (handshaking) throw connection_error("TLS took too long to begin");
                return false;
            }
            std::array<char, 16384> buffer;
            std::size_t n = socket_.receive(buffer);
            try {
                client_->received_data(std::span(reinterpret_cast<const std::uint8_t*>(buffer.data()), n));
            } catch (const std::exception& e) {
                throw connection_error(std::string("TLS: ") + e.what());
            }
            if (closed_ && plain_.empty()) throw connection_error("the server closed the connection");
            return true;
        }

        detail::socket socket_;
        std::shared_ptr<callbacks> callbacks_;
        std::unique_ptr<Botan::TLS::Client> client_;
        std::vector<char> plain_;
        bool closed_ = false;
    };

#else

    // TLS by OpenSSL, checking the server's certificate against the system's roots.
    class tls_transport : public transport {
    public:
        tls_transport(const std::string& host, const std::string& port, std::vector<std::string> protocols)
            : socket_(host, port) {
            context_ = SSL_CTX_new(TLS_client_method());
            if (!context_) throw connection_error("OpenSSL can't make a TLS context");
            SSL_CTX_set_min_proto_version(context_, TLS1_2_VERSION);
            SSL_CTX_set_default_verify_paths(context_);
            SSL_CTX_set_verify(context_, SSL_VERIFY_PEER, nullptr);
            std::string wire;  // ALPN's list: each name after its length
            for (const auto& p : protocols) {
                wire += static_cast<char>(p.size());
                wire += p;
            }
            SSL_CTX_set_alpn_protos(context_, reinterpret_cast<const unsigned char*>(wire.data()), static_cast<unsigned>(wire.size()));
            session_ = SSL_new(context_);
            SSL_set_fd(session_, socket_.descriptor());
            SSL_set_tlsext_host_name(session_, host.c_str());
            SSL_set1_host(session_, host.c_str());
            if (SSL_connect(session_) != 1) throw connection_error("TLS with " + host + " failed: " + last_error());
        }
        ~tls_transport() override {
            if (session_) {
                SSL_shutdown(session_);
                SSL_free(session_);
            }
            if (context_) SSL_CTX_free(context_);
        }

        std::optional<std::size_t> read(std::span<char> out, milliseconds wait) override {
            for (;;) {
                if (SSL_pending(session_) == 0 && !socket_.readable(wait)) return std::nullopt;
                int n = SSL_read(session_, out.data(), static_cast<int>(out.size()));
                if (n > 0) return static_cast<std::size_t>(n);
                int reason = SSL_get_error(session_, n);
                if (reason == SSL_ERROR_WANT_READ) continue;  // only part of a record came
                if (reason == SSL_ERROR_ZERO_RETURN) throw connection_error("the server closed the connection");
                throw connection_error("TLS read: " + last_error());
            }
        }
        void write(std::string_view data) override {
            while (!data.empty()) {
                int n = SSL_write(session_, data.data(), static_cast<int>(data.size()));
                if (n <= 0) throw connection_error("TLS write: " + last_error());
                data.remove_prefix(static_cast<std::size_t>(n));
            }
        }
        std::string protocol() const override {
            const unsigned char* name = nullptr;
            unsigned length = 0;
            SSL_get0_alpn_selected(session_, &name, &length);
            return std::string(reinterpret_cast<const char*>(name), length);
        }

    private:
        static std::string last_error() {
            char text[256];
            ERR_error_string_n(ERR_get_error(), text, sizeof text);
            return text;
        }

        detail::socket socket_;
        SSL_CTX* context_ = nullptr;
        SSL* session_ = nullptr;
    };

#endif

    // ---------------------------------------------------------------------------
    // HTTP/2 (RFC 9113), the part a client of one long stream needs
    // ---------------------------------------------------------------------------

    namespace http2 {

        enum frame_type : std::uint8_t {
            data_frame = 0, headers_frame = 1, priority_frame = 2, reset_frame = 3, settings_frame = 4,
            push_frame = 5, ping_frame = 6, goaway_frame = 7, window_frame = 8, continuation_frame = 9,
        };
        enum frame_flag : std::uint8_t { end_stream = 0x1, acknowledge = 0x1, end_headers = 0x4, padded = 0x8, priority = 0x20 };

        struct frame {
            frame_type type;
            std::uint8_t flags;
            std::uint32_t stream;
            std::string payload;
        };

        // What happened on a stream, as the connection reads it.
        struct event {
            enum class kind { headers, data, reset } type = kind::data;
            std::uint32_t stream = 0;
            bool ended = false;  // END_STREAM: the server sends nothing more on it
            std::vector<hpack::header> headers;
            std::string data;
            std::uint32_t reset_code = 0;
        };

        class connection {
        public:
            // Our windows are made large at once, and topped up as data is read, so the
            // server never waits on us for a live stream that may stay open for hours.
            static constexpr std::uint32_t window = 16 * 1024 * 1024;

            explicit connection(std::unique_ptr<transport> link) : link_(std::move(link)) {
                std::string start = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                std::string settings;
                append_setting(settings, 0x2, 0);       // ENABLE_PUSH: no
                append_setting(settings, 0x4, window);  // INITIAL_WINDOW_SIZE
                start += encode_frame(settings_frame, 0, 0, settings);
                start += encode_frame(window_frame, 0, 0, be32(window - 65535));
                link_->write(start);
            }

            std::uint32_t open(const std::vector<hpack::header>& headers) {
                std::uint32_t id = next_stream_;
                next_stream_ += 2;
                std::string block = hpack::encode(headers);
                // A header block bigger than a frame continues in CONTINUATION frames.
                std::size_t limit = peer_frame_size_;
                bool first = true;
                std::string out;
                do {
                    std::string piece = block.substr(0, limit);
                    block.erase(0, piece.size());
                    std::uint8_t flags = block.empty() ? end_headers : 0;
                    out += encode_frame(first ? headers_frame : continuation_frame, flags, id, piece);
                    first = false;
                } while (!block.empty());
                link_->write(out);
                return id;
            }

            void send(std::uint32_t stream, std::string_view data, bool last) {
                // Our messages are small; one larger than a frame is cut into several.
                std::string out;
                do {
                    std::string_view piece = data.substr(0, peer_frame_size_);
                    data.remove_prefix(piece.size());
                    out += encode_frame(data_frame, (data.empty() && last) ? end_stream : 0, stream, piece);
                } while (!data.empty());
                link_->write(out);
            }

            void reset(std::uint32_t stream, std::uint32_t code = 0x8 /* CANCEL */) {
                link_->write(encode_frame(reset_frame, 0, stream, be32(code)));
            }

            void ping(std::string_view opaque = std::string_view("ember\0\0\0", 8)) {
                link_->write(encode_frame(ping_frame, 0, 0, std::string(opaque)));
            }

            // The next thing that happened on a stream, after answering what the
            // connection itself asks (settings, pings). Nothing if `wait` passes first.
            std::optional<event> next(milliseconds wait) {
                auto deadline = std::chrono::steady_clock::now() + wait;
                for (;;) {
                    auto f = read_frame(deadline);
                    if (!f) return std::nullopt;
                    last_heard_ = std::chrono::steady_clock::now();
                    if (auto e = handle(*f)) return e;
                }
            }

            // When the server last sent anything at all.
            std::chrono::steady_clock::time_point last_heard() const { return last_heard_; }

        private:
            static void append_setting(std::string& out, std::uint16_t id, std::uint32_t value) {
                out += static_cast<char>(id >> 8);
                out += static_cast<char>(id);
                out += be32(value);
            }
            static std::string be32(std::uint32_t n) {
                return {static_cast<char>(n >> 24), static_cast<char>(n >> 16), static_cast<char>(n >> 8), static_cast<char>(n)};
            }
            static std::uint32_t read32(std::string_view s, std::size_t at) {
                return (std::uint32_t(std::uint8_t(s[at])) << 24) | (std::uint32_t(std::uint8_t(s[at + 1])) << 16) |
                       (std::uint32_t(std::uint8_t(s[at + 2])) << 8) | std::uint32_t(std::uint8_t(s[at + 3]));
            }
            static std::string encode_frame(frame_type type, std::uint8_t flags, std::uint32_t stream, std::string_view payload) {
                std::string out;
                auto length = static_cast<std::uint32_t>(payload.size());
                out += static_cast<char>(length >> 16);
                out += static_cast<char>(length >> 8);
                out += static_cast<char>(length);
                out += static_cast<char>(type);
                out += static_cast<char>(flags);
                out += be32(stream & 0x7fffffff);
                out += payload;
                return out;
            }

            std::optional<frame> read_frame(std::chrono::steady_clock::time_point deadline) {
                while (inbound_.size() < 9 || inbound_.size() < 9 + frame_length()) {
                    auto left = std::chrono::duration_cast<milliseconds>(deadline - std::chrono::steady_clock::now());
                    if (left.count() < 0) left = milliseconds(0);
                    std::array<char, 16384> buffer;
                    auto n = link_->read(buffer, left);
                    if (!n) return std::nullopt;
                    inbound_.append(buffer.data(), *n);
                }
                frame f;
                std::size_t length = frame_length();
                f.type = static_cast<frame_type>(inbound_[3]);
                f.flags = static_cast<std::uint8_t>(inbound_[4]);
                f.stream = read32(inbound_, 5) & 0x7fffffff;
                f.payload = inbound_.substr(9, length);
                inbound_.erase(0, 9 + length);
                return f;
            }
            std::size_t frame_length() const {
                return (std::size_t(std::uint8_t(inbound_[0])) << 16) | (std::size_t(std::uint8_t(inbound_[1])) << 8) |
                       std::size_t(std::uint8_t(inbound_[2]));
            }

            // Takes padding, and a HEADERS frame's priority, off a payload.
            static std::string_view content(const frame& f) {
                std::string_view p = f.payload;
                std::size_t pad = 0;
                if (f.flags & padded) {
                    if (p.empty()) throw failure("a padded frame has no padding length");
                    pad = std::uint8_t(p[0]);
                    p.remove_prefix(1);
                }
                if (f.type == headers_frame && (f.flags & priority)) {
                    if (p.size() < 5) throw failure("a HEADERS frame's priority is cut short");
                    p.remove_prefix(5);
                }
                if (pad > p.size()) throw failure("a frame's padding is longer than the frame");
                p.remove_suffix(pad);
                return p;
            }

            std::optional<event> handle(const frame& f) {
                switch (f.type) {
                    case settings_frame: {
                        if (f.flags & acknowledge) return std::nullopt;
                        for (std::size_t at = 0; at + 6 <= f.payload.size(); at += 6) {
                            auto id = (std::uint16_t(std::uint8_t(f.payload[at])) << 8) | std::uint8_t(f.payload[at + 1]);
                            if (id == 0x5) peer_frame_size_ = read32(f.payload, at + 2);  // MAX_FRAME_SIZE
                        }
                        link_->write(encode_frame(settings_frame, acknowledge, 0, {}));
                        return std::nullopt;
                    }
                    case ping_frame:
                        if (!(f.flags & acknowledge)) link_->write(encode_frame(ping_frame, acknowledge, 0, f.payload));
                        return std::nullopt;
                    case goaway_frame: {
                        std::uint32_t code = f.payload.size() >= 8 ? read32(f.payload, 4) : 0;
                        std::string detail = f.payload.size() > 8 ? f.payload.substr(8) : "";
                        throw connection_error("the server is ending the connection (GOAWAY " + std::to_string(code) +
                                               (detail.empty() ? "" : ": " + detail) + ")");
                    }
                    case window_frame:
                    case priority_frame:
                        return std::nullopt;  // we send too little to wait on the server's windows
                    case push_frame:
                        throw failure("the server pushed, which we turned off");
                    case reset_frame: {
                        event e;
                        e.type = event::kind::reset;
                        e.stream = f.stream;
                        e.ended = true;
                        e.reset_code = f.payload.size() >= 4 ? read32(f.payload, 0) : 0;
                        return e;
                    }
                    case data_frame: {
                        event e;
                        e.type = event::kind::data;
                        e.stream = f.stream;
                        e.ended = f.flags & end_stream;
                        e.data = std::string(content(f));
                        // Give back what was read, whole frame and padding, once enough
                        // has gathered to be worth a frame of its own.
                        consumed_ += f.payload.size();
                        if (consumed_ >= window / 4) {
                            std::string out = encode_frame(window_frame, 0, 0, be32(static_cast<std::uint32_t>(consumed_)));
                            if (!e.ended) out += encode_frame(window_frame, 0, f.stream, be32(static_cast<std::uint32_t>(consumed_)));
                            link_->write(out);
                            consumed_ = 0;
                        }
                        return e;
                    }
                    case headers_frame:
                    case continuation_frame: {
                        if (f.type == headers_frame) {
                            block_ = std::string(content(f));
                            block_stream_ = f.stream;
                            block_ended_ = f.flags & end_stream;
                        } else {
                            if (f.stream != block_stream_) throw failure("a CONTINUATION frame is on the wrong stream");
                            block_ += f.payload;
                        }
                        if (!(f.flags & end_headers)) return std::nullopt;
                        event e;
                        e.type = event::kind::headers;
                        e.stream = block_stream_;
                        e.ended = block_ended_;
                        e.headers = decoder_.decode(block_);
                        return e;
                    }
                }
                return std::nullopt;  // a frame type we don't know is skipped, as the RFC says
            }

            std::unique_ptr<transport> link_;
            hpack::decoder decoder_;
            std::string inbound_;
            std::uint32_t next_stream_ = 1;
            std::size_t peer_frame_size_ = 16384;
            std::size_t consumed_ = 0;
            std::string block_;
            std::uint32_t block_stream_ = 0;
            bool block_ended_ = false;
            std::chrono::steady_clock::time_point last_heard_ = std::chrono::steady_clock::now();
        };

    }  // namespace http2

    // ---------------------------------------------------------------------------
    // gRPC over HTTP/2: messages each after a flag byte and a 4-byte length
    // ---------------------------------------------------------------------------

    namespace grpc {

        inline std::string frame_message(std::string_view message) {
            auto n = static_cast<std::uint32_t>(message.size());
            std::string out{'\0', static_cast<char>(n >> 24), static_cast<char>(n >> 16), static_cast<char>(n >> 8), static_cast<char>(n)};
            out += message;
            return out;
        }

        // The percent-decoding gRPC uses for grpc-message.
        inline std::string unescape(std::string_view text) {
            std::string out;
            for (std::size_t i = 0; i < text.size(); ++i) {
                if (text[i] == '%' && i + 2 < text.size()) {
                    out += static_cast<char>(std::stoi(std::string(text.substr(i + 1, 2)), nullptr, 16));
                    i += 2;
                } else {
                    out += text[i];
                }
            }
            return out;
        }

        // One call's incoming messages, put back together from DATA frames.
        class messages {
        public:
            void add(std::string_view data) { buffer_ += data; }
            std::optional<std::string> next() {
                if (buffer_.size() < 5) return std::nullopt;
                if (buffer_[0] != 0) throw failure("the server compressed a message, which we didn't ask for");
                std::size_t length = (std::size_t(std::uint8_t(buffer_[1])) << 24) | (std::size_t(std::uint8_t(buffer_[2])) << 16) |
                                     (std::size_t(std::uint8_t(buffer_[3])) << 8) | std::size_t(std::uint8_t(buffer_[4]));
                if (buffer_.size() < 5 + length) return std::nullopt;
                std::string out = buffer_.substr(5, length);
                buffer_.erase(0, 5 + length);
                return out;
            }

        private:
            std::string buffer_;
        };

        // The status in a call's trailers: 0 is OK.
        inline void check(const std::vector<hpack::header>& headers) {
            int code = -1;
            std::string message;
            for (const auto& [name, value] : headers) {
                if (name == "grpc-status") code = std::stoi(value);
                if (name == "grpc-message") message = unescape(value);
                if (name == ":status" && value != "200") throw status_error(14, "the server answered HTTP " + value);
            }
            if (code > 0) throw status_error(code, message);
        }

    }  // namespace grpc

    // ---------------------------------------------------------------------------
    // Where to connect, and what a document is at one moment
    // ---------------------------------------------------------------------------

    struct options {
        std::string project;         // the Firebase project's id
        std::string api_key;         // the web API key Auth's calls name; any will do for the emulators
        std::string firestore_host;  // host:port; empty is Firestore itself, or FIRESTORE_EMULATOR_HOST when set
        std::string auth_host;       // host:port; empty is Google's Auth, or FIREBASE_AUTH_EMULATOR_HOST when set
        std::string database = "(default)";
        // Where the client says what it's doing, like reconnecting. Quiet when empty.
        std::function<void(std::string_view)> log;

        static options for_project(std::string project) {
            options o;
            o.project = std::move(project);
            return o;
        }

        std::string database_name() const { return "projects/" + project + "/databases/" + database; }

        // Where Firestore is: a host given, or the emulator's, is spoken to in plain
        // HTTP/2 unless its port is 443; Firestore itself, over TLS.
        struct place {
            std::string host, port;
            bool secure = true;
            bool emulator = false;
        };
        place firestore() const {
            std::string where = firestore_host;
            if (where.empty()) {
                if (const char* emulator = std::getenv("FIRESTORE_EMULATOR_HOST"); emulator && *emulator) where = emulator;
            }
            if (where.empty()) return {"firestore.googleapis.com", "443", true, false};
            auto colon = where.rfind(':');
            place p;
            p.host = where.substr(0, colon);
            p.port = colon == std::string::npos ? "8080" : where.substr(colon + 1);
            p.secure = p.port == "443";
            p.emulator = !p.secure;
            return p;
        }
        // The start of Auth's addresses: Google's, or the emulator's, which serves
        // both Identity Toolkit and Secure Token under its own host.
        std::string identity_toolkit() const { return auth_base("identitytoolkit.googleapis.com"); }
        std::string secure_token() const { return auth_base("securetoken.googleapis.com"); }

    private:
        std::string auth_base(const std::string& service) const {
            std::string where = auth_host;
            if (where.empty()) {
                if (const char* emulator = std::getenv("FIREBASE_AUTH_EMULATOR_HOST"); emulator && *emulator) where = emulator;
            }
            if (where.empty()) return "https://" + service;
            return (where.ends_with(":443") ? "https://" : "http://") + where + "/" + service;
        }
    };

    // A document as it was at one consistent moment.
    struct snapshot {
        std::string path;  // like views/projects::issue_page:neotrac-42
        bool exists = false;
        bool from_cache = false;  // told from what's known while the connection is down
        value data = value::map();  // its fields
        timestamp update_time;
    };

    inline std::string to_json(const snapshot& s) {
        std::string out = "{\"path\":";
        detail::append_escaped(out, s.path);
        out += ",\"exists\":";
        out += s.exists ? "true" : "false";
        if (s.exists) {
            out += ",\"update_time\":";
            detail::append_escaped(out, to_string(s.update_time));
            out += ",\"data\":";
            to_json(s.data, out);
        }
        return out + "}";
    }

    // ---------------------------------------------------------------------------
    // JSON, for Auth's answers and a uione backend's
    // ---------------------------------------------------------------------------

    namespace detail {

        class json_reader {
        public:
            explicit json_reader(std::string_view text) : text_(text) {}

            value document() {
                value v = read();
                space();
                if (at_ != text_.size()) fail("there's more after the JSON");
                return v;
            }

        private:
            [[noreturn]] void fail(const std::string& what) { throw failure(0, "bad JSON: " + what); }
            void space() {
                while (at_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[at_]))) ++at_;
            }
            bool take(std::string_view word) {
                if (text_.substr(at_, word.size()) != word) return false;
                at_ += word.size();
                return true;
            }
            value read() {
                space();
                if (at_ >= text_.size()) fail("it ends early");
                char c = text_[at_];
                if (c == '{') return object();
                if (c == '[') return array();
                if (c == '"') return value(string());
                if (take("true")) return value(true);
                if (take("false")) return value(false);
                if (take("null")) return value();
                if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return number();
                fail(std::string("unexpected '") + c + "'");
            }
            value object() {
                ++at_;
                std::map<std::string, value> fields;
                space();
                if (at_ < text_.size() && text_[at_] == '}') {
                    ++at_;
                    return value(std::move(fields));
                }
                for (;;) {
                    space();
                    if (at_ >= text_.size() || text_[at_] != '"') fail("a name is expected");
                    std::string name = string();
                    space();
                    if (!take(":")) fail("':' is expected");
                    fields[name] = read();
                    space();
                    if (take(",")) continue;
                    if (take("}")) return value(std::move(fields));
                    fail("',' or '}' is expected");
                }
            }
            value array() {
                ++at_;
                std::vector<value> items;
                space();
                if (take("]")) return value(std::move(items));
                for (;;) {
                    items.push_back(read());
                    space();
                    if (take(",")) continue;
                    if (take("]")) return value(std::move(items));
                    fail("',' or ']' is expected");
                }
            }
            value number() {
                std::size_t start = at_;
                bool whole = true;
                if (text_[at_] == '-') ++at_;
                while (at_ < text_.size()) {
                    char c = text_[at_];
                    if (std::isdigit(static_cast<unsigned char>(c))) {
                        ++at_;
                    } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                        whole = false;
                        ++at_;
                    } else {
                        break;
                    }
                }
                std::string digits(text_.substr(start, at_ - start));
                try {
                    if (whole) return value(static_cast<long long>(std::stoll(digits)));
                    return value(std::stod(digits));
                } catch (const std::exception&) {
                    if (whole) return value(std::stod(digits));  // too big for 64 bits
                    fail("'" + digits + "' isn't a number");
                }
            }
            unsigned hex4() {
                if (at_ + 4 > text_.size()) fail("a \\u escape ends early");
                unsigned n = 0;
                for (int i = 0; i < 4; ++i) {
                    char c = text_[at_++];
                    n <<= 4;
                    if (c >= '0' && c <= '9') n |= c - '0';
                    else if (c >= 'a' && c <= 'f') n |= c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F') n |= c - 'A' + 10;
                    else fail("a \\u escape holds a letter that isn't hex");
                }
                return n;
            }
            static void utf8(std::string& out, unsigned point) {
                if (point < 0x80) {
                    out += static_cast<char>(point);
                } else if (point < 0x800) {
                    out += static_cast<char>(0xc0 | (point >> 6));
                    out += static_cast<char>(0x80 | (point & 0x3f));
                } else if (point < 0x10000) {
                    out += static_cast<char>(0xe0 | (point >> 12));
                    out += static_cast<char>(0x80 | ((point >> 6) & 0x3f));
                    out += static_cast<char>(0x80 | (point & 0x3f));
                } else {
                    out += static_cast<char>(0xf0 | (point >> 18));
                    out += static_cast<char>(0x80 | ((point >> 12) & 0x3f));
                    out += static_cast<char>(0x80 | ((point >> 6) & 0x3f));
                    out += static_cast<char>(0x80 | (point & 0x3f));
                }
            }
            std::string string() {
                ++at_;  // the opening quote
                std::string out;
                for (;;) {
                    if (at_ >= text_.size()) fail("a string isn't closed");
                    char c = text_[at_++];
                    if (c == '"') return out;
                    if (c != '\\') {
                        out += c;
                        continue;
                    }
                    if (at_ >= text_.size()) fail("an escape ends early");
                    switch (char e = text_[at_++]) {
                        case '"': out += '"'; break;
                        case '\\': out += '\\'; break;
                        case '/': out += '/'; break;
                        case 'b': out += '\b'; break;
                        case 'f': out += '\f'; break;
                        case 'n': out += '\n'; break;
                        case 'r': out += '\r'; break;
                        case 't': out += '\t'; break;
                        case 'u': {
                            unsigned point = hex4();
                            // A character past the first 65536 comes as two halves.
                            if (point >= 0xd800 && point < 0xdc00 && text_.substr(at_, 2) == "\\u") {
                                at_ += 2;
                                unsigned low = hex4();
                                point = 0x10000 + ((point - 0xd800) << 10) + (low - 0xdc00);
                            }
                            utf8(out, point);
                            break;
                        }
                        default: fail(std::string("an unknown escape \\") + e);
                    }
                }
            }

            std::string_view text_;
            std::size_t at_ = 0;
        };

        // base64url, as a JWT's parts are written, padded or not.
        inline std::string base64url_decode(std::string_view in) {
            auto digit = [](char c) -> int {
                if (c >= 'A' && c <= 'Z') return c - 'A';
                if (c >= 'a' && c <= 'z') return c - 'a' + 26;
                if (c >= '0' && c <= '9') return c - '0' + 52;
                if (c == '-' || c == '+') return 62;
                if (c == '_' || c == '/') return 63;
                return -1;
            };
            std::string out;
            std::uint32_t bits = 0;
            int count = 0;
            for (char c : in) {
                if (c == '=') break;
                int d = digit(c);
                if (d < 0) throw failure(0, "a token isn't base64url");
                bits = (bits << 6) | static_cast<std::uint32_t>(d);
                count += 6;
                if (count >= 8) {
                    count -= 8;
                    out += static_cast<char>((bits >> count) & 0xff);
                }
            }
            return out;
        }

        // The %-encoding of a form's values.
        inline std::string form_encode(std::string_view text) {
            std::string out;
            for (unsigned char c : text) {
                if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                    out += static_cast<char>(c);
                } else {
                    char hex[4];
                    std::snprintf(hex, sizeof hex, "%%%02X", c);
                    out += hex;
                }
            }
            return out;
        }

    }  // namespace detail

    // Reads JSON: an object is a map, an array an array, a whole number an integer and
    // any other a double. Throws failure, status 0, when it isn't JSON.
    inline value parse_json(std::string_view text) { return detail::json_reader(text).document(); }

    // ---------------------------------------------------------------------------
    // HTTP/1.1, for REST calls: Auth's, and a uione backend's commands
    // ---------------------------------------------------------------------------

    struct response {
        int status = 0;
        std::string body;
    };

    namespace detail {

        struct address {
            bool secure = true;
            std::string host, port, target;  // target: the path and query
        };

        inline address parse_url(const std::string& url) {
            address a;
            std::string_view rest = url;
            if (rest.starts_with("https://")) {
                rest.remove_prefix(8);
            } else if (rest.starts_with("http://")) {
                a.secure = false;
                rest.remove_prefix(7);
            } else {
                throw failure(0, "an address starts with https:// or http://: " + url);
            }
            auto slash = rest.find('/');
            std::string_view authority = rest.substr(0, slash);
            a.target = slash == std::string_view::npos ? "/" : std::string(rest.substr(slash));
            auto colon = authority.rfind(':');
            if (colon == std::string_view::npos) {
                a.host = std::string(authority);
                a.port = a.secure ? "443" : "80";
            } else {
                a.host = std::string(authority.substr(0, colon));
                a.port = std::string(authority.substr(colon + 1));
            }
            return a;
        }

        inline response http_exchange(const std::string& method, const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers,
                                      const std::string* body) {
            address a = parse_url(url);
            std::unique_ptr<transport> link;
            if (a.secure) link = std::make_unique<tls_transport>(a.host, a.port, std::vector<std::string>{"http/1.1"});
            else link = std::make_unique<plain_transport>(a.host, a.port);
            std::string request = method + " " + a.target + " HTTP/1.1\r\nHost: " + a.host + "\r\nConnection: close\r\nUser-Agent: ember/" EMBER_VERSION "\r\n";
            bool typed = false;
            for (const auto& [name, value] : headers) {
                request += name + ": " + value + "\r\n";
                std::string lower = name;
                std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
                if (lower == "content-type") typed = true;
            }
            if (body) {
                if (!typed) request += "Content-Type: application/json\r\n";
                request += "Content-Length: " + std::to_string(body->size()) + "\r\n\r\n" + *body;
            } else {
                request += "\r\n";
            }
            link->write(request);

            // Read until the answer is whole: its length said, its chunks ended, or the
            // connection closed.
            std::string in;
            std::array<char, 16384> buffer;
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
            std::size_t head_end = std::string::npos;
            std::optional<std::size_t> length;
            bool chunked = false;
            response out;
            auto whole = [&]() -> bool {
                if (head_end == std::string::npos) return false;
                std::string_view rest = std::string_view(in).substr(head_end);
                if (length) return rest.size() >= *length;
                if (!chunked) return false;
                // Chunks: a hex size, a line, the data, a line; a size of 0 ends them.
                std::size_t at = 0;
                for (;;) {
                    auto line = rest.find("\r\n", at);
                    if (line == std::string_view::npos) return false;
                    std::size_t size = std::stoul(std::string(rest.substr(at, line - at)), nullptr, 16);
                    if (size == 0) return rest.find("\r\n", line + 2) != std::string_view::npos;
                    at = line + 2 + size + 2;
                    if (at > rest.size()) return false;
                }
            };
            for (;;) {
                if (whole()) break;
                auto left = std::chrono::duration_cast<milliseconds>(deadline - std::chrono::steady_clock::now());
                if (left.count() <= 0) throw connection_error("no answer from " + a.host + " within a minute");
                std::optional<std::size_t> n;
                try {
                    n = link->read(buffer, left);
                } catch (const connection_error&) {
                    if (head_end != std::string::npos && !length && !chunked) break;  // closed: the answer is what came
                    throw;
                }
                if (!n) continue;
                in.append(buffer.data(), *n);
                if (head_end == std::string::npos) {
                    auto end = in.find("\r\n\r\n");
                    if (end == std::string::npos) continue;
                    head_end = end + 4;
                    std::string_view head = std::string_view(in).substr(0, end);
                    auto first = head.find("\r\n");
                    std::string_view status = head.substr(0, first);
                    auto space = status.find(' ');
                    if (space == std::string_view::npos) throw failure(0, "a strange answer from " + a.host);
                    out.status = std::stoi(std::string(status.substr(space + 1, 3)));
                    std::size_t at = first == std::string_view::npos ? head.size() : first + 2;
                    while (at < head.size()) {
                        auto next = head.find("\r\n", at);
                        std::string_view line = head.substr(at, next == std::string_view::npos ? std::string_view::npos : next - at);
                        at = next == std::string_view::npos ? head.size() : next + 2;
                        auto colon = line.find(':');
                        if (colon == std::string_view::npos) continue;
                        std::string name(line.substr(0, colon));
                        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });
                        std::string_view value = line.substr(colon + 1);
                        while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
                        if (name == "content-length") length = std::stoul(std::string(value));
                        if (name == "transfer-encoding" && value.find("chunked") != std::string_view::npos) chunked = true;
                    }
                    if (method == "HEAD" || out.status == 204 || out.status == 304) length = 0;
                }
            }
            std::string_view rest = std::string_view(in).substr(head_end);
            if (length) {
                out.body = std::string(rest.substr(0, *length));
            } else if (chunked) {
                std::size_t at = 0;
                for (;;) {
                    auto line = rest.find("\r\n", at);
                    std::size_t size = std::stoul(std::string(rest.substr(at, line - at)), nullptr, 16);
                    if (size == 0) break;
                    out.body += rest.substr(line + 2, size);
                    at = line + 2 + size + 2;
                }
            } else {
                out.body = std::string(rest);
            }
            return out;
        }

    }  // namespace detail

    // An HTTP POST, over TLS for https://, plain for http://. Its body is JSON unless a
    // Content-Type header says otherwise. Any status comes back; only a connection that
    // fails throws.
    inline response https_post(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers, const std::string& body) {
        return detail::http_exchange("POST", url, headers, &body);
    }

    inline response https_get(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers) {
        return detail::http_exchange("GET", url, headers, nullptr);
    }

    // An HTTP PUT, like an upload to an address Cloud Storage signed.
    inline response https_put(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers, const std::string& body) {
        return detail::http_exchange("PUT", url, headers, &body);
    }

    // ---------------------------------------------------------------------------
    // Firestore's messages
    // ---------------------------------------------------------------------------

    namespace firestore {

        // google.firestore.v1 messages, read and written by field number.

        inline timestamp read_timestamp(std::string_view data) {
            timestamp t;
            protobuf::reader in(data);
            int field;
            protobuf::wire type;
            while (in.next(field, type)) {
                if (field == 1 && type == protobuf::varint_wire) t.seconds = static_cast<std::int64_t>(in.varint());
                else if (field == 2 && type == protobuf::varint_wire) t.nanos = static_cast<std::int32_t>(in.varint());
                else in.skip(type);
            }
            return t;
        }

        value read_value(std::string_view data);

        // A map<string, Value>'s entries: key = 1, value = 2.
        inline std::pair<std::string, value> read_entry(std::string_view data) {
            std::pair<std::string, value> out;
            protobuf::reader in(data);
            int field;
            protobuf::wire type;
            while (in.next(field, type)) {
                if (field == 1 && type == protobuf::length_wire) out.first = std::string(in.bytes());
                else if (field == 2 && type == protobuf::length_wire) out.second = read_value(in.bytes());
                else in.skip(type);
            }
            return out;
        }

        inline value read_value(std::string_view data) {
            value v;
            protobuf::reader in(data);
            int field;
            protobuf::wire type;
            while (in.next(field, type)) {
                switch (field) {
                    case 11: in.skip(type); v.type = value::kind::null; break;
                    case 1: v.type = value::kind::boolean; v.boolean = in.varint() != 0; break;
                    case 2: v.type = value::kind::integer; v.integer = static_cast<std::int64_t>(in.varint()); break;
                    case 3: v.type = value::kind::floating; v.floating = in.floating(); break;
                    case 10: v.type = value::kind::time; v.time = read_timestamp(in.bytes()); break;
                    case 17: v.type = value::kind::string; v.text = std::string(in.bytes()); break;
                    case 18: v.type = value::kind::bytes; v.text = std::string(in.bytes()); break;
                    case 5: v.type = value::kind::reference; v.text = std::string(in.bytes()); break;
                    case 8: {  // google.type.LatLng: latitude = 1, longitude = 2
                        v.type = value::kind::point;
                        protobuf::reader point(in.bytes());
                        int f;
                        protobuf::wire t;
                        while (point.next(f, t)) {
                            if (f == 1 && t == protobuf::fixed64_wire) v.point.latitude = point.floating();
                            else if (f == 2 && t == protobuf::fixed64_wire) v.point.longitude = point.floating();
                            else point.skip(t);
                        }
                        break;
                    }
                    case 9: {  // ArrayValue: values = 1
                        v.type = value::kind::array;
                        protobuf::reader array(in.bytes());
                        int f;
                        protobuf::wire t;
                        while (array.next(f, t)) {
                            if (f == 1 && t == protobuf::length_wire) v.items.push_back(read_value(array.bytes()));
                            else array.skip(t);
                        }
                        break;
                    }
                    case 6: {  // MapValue: fields = 1
                        v.type = value::kind::map;
                        protobuf::reader map(in.bytes());
                        int f;
                        protobuf::wire t;
                        while (map.next(f, t)) {
                            if (f == 1 && t == protobuf::length_wire) v.fields.insert(read_entry(map.bytes()));
                            else map.skip(t);
                        }
                        break;
                    }
                    default: in.skip(type);
                }
            }
            return v;
        }

        struct document {
            std::string name;
            value fields = value::map();
            timestamp create_time;
            timestamp update_time;
        };

        inline document read_document(std::string_view data) {
            document d;
            protobuf::reader in(data);
            int field;
            protobuf::wire type;
            while (in.next(field, type)) {
                if (field == 1 && type == protobuf::length_wire) d.name = std::string(in.bytes());
                else if (field == 2 && type == protobuf::length_wire) d.fields.fields.insert(read_entry(in.bytes()));
                else if (field == 3 && type == protobuf::length_wire) d.create_time = read_timestamp(in.bytes());
                else if (field == 4 && type == protobuf::length_wire) d.update_time = read_timestamp(in.bytes());
                else in.skip(type);
            }
            return d;
        }

        enum class change_type { no_change = 0, add = 1, remove = 2, current = 3, reset = 4 };

        // One ListenResponse, flattened: which of its five kinds it is, and what it says.
        struct listen_response {
            enum class kind { none, target_change, document_change, document_delete, document_remove, filter } type = kind::none;
            change_type change = change_type::no_change;
            std::vector<std::int32_t> target_ids;          // the targets it's about
            std::vector<std::int32_t> removed_target_ids;  // the targets a document left
            int cause_code = 0;
            std::string cause_message;
            std::string resume_token;
            std::optional<timestamp> read_time;
            document changed;              // for document_change
            std::string document_name;     // for delete and remove
            std::int32_t count = 0;        // for filter
        };

        inline void read_status(std::string_view data, listen_response& out) {
            protobuf::reader in(data);  // google.rpc.Status: code = 1, message = 2
            int field;
            protobuf::wire type;
            while (in.next(field, type)) {
                if (field == 1 && type == protobuf::varint_wire) out.cause_code = static_cast<int>(in.varint());
                else if (field == 2 && type == protobuf::length_wire) out.cause_message = std::string(in.bytes());
                else in.skip(type);
            }
        }

        inline listen_response read_listen_response(std::string_view data) {
            listen_response out;
            protobuf::reader in(data);
            int field;
            protobuf::wire type;
            while (in.next(field, type)) {
                if (type != protobuf::length_wire) {
                    in.skip(type);
                    continue;
                }
                protobuf::reader inner(in.bytes());
                int f;
                protobuf::wire t;
                switch (field) {
                    case 2:  // TargetChange
                        out.type = listen_response::kind::target_change;
                        while (inner.next(f, t)) {
                            if (f == 1 && t == protobuf::varint_wire) out.change = static_cast<change_type>(inner.varint());
                            else if (f == 2) inner.integers(t, out.target_ids);
                            else if (f == 3 && t == protobuf::length_wire) read_status(inner.bytes(), out);
                            else if (f == 4 && t == protobuf::length_wire) out.resume_token = std::string(inner.bytes());
                            else if (f == 6 && t == protobuf::length_wire) out.read_time = read_timestamp(inner.bytes());
                            else inner.skip(t);
                        }
                        break;
                    case 3:  // DocumentChange
                        out.type = listen_response::kind::document_change;
                        while (inner.next(f, t)) {
                            if (f == 1 && t == protobuf::length_wire) out.changed = read_document(inner.bytes());
                            else if (f == 5) inner.integers(t, out.target_ids);
                            else if (f == 6) inner.integers(t, out.removed_target_ids);
                            else inner.skip(t);
                        }
                        break;
                    case 4:  // DocumentDelete: removed_target_ids = 6
                    case 6:  // DocumentRemove: removed_target_ids = 2
                        out.type = field == 4 ? listen_response::kind::document_delete : listen_response::kind::document_remove;
                        while (inner.next(f, t)) {
                            if (f == 1 && t == protobuf::length_wire) out.document_name = std::string(inner.bytes());
                            else if (f == (field == 4 ? 6 : 2)) inner.integers(t, out.removed_target_ids);
                            else if (f == 4 && t == protobuf::length_wire) out.read_time = read_timestamp(inner.bytes());
                            else inner.skip(t);
                        }
                        break;
                    case 5:  // ExistenceFilter
                        out.type = listen_response::kind::filter;
                        while (inner.next(f, t)) {
                            if (f == 1 && t == protobuf::varint_wire) out.target_ids.push_back(static_cast<std::int32_t>(inner.varint()));
                            else if (f == 2 && t == protobuf::varint_wire) out.count = static_cast<std::int32_t>(inner.varint());
                            else inner.skip(t);
                        }
                        break;
                    default:
                        break;
                }
            }
            return out;
        }

        // ListenRequest{database = 1, add_target = 2: Target{documents = 3:
        // DocumentsTarget{documents = 2}, resume_token = 4, target_id = 5}}.
        inline std::string add_document_target(const std::string& database, const std::string& document,
                                               std::int32_t target_id, const std::string& resume_token) {
            protobuf::writer documents;
            documents.bytes(2, document);
            protobuf::writer target;
            target.message(3, documents);
            if (!resume_token.empty()) target.bytes(4, resume_token);
            target.integer(5, target_id);
            protobuf::writer request;
            request.bytes(1, database);
            request.message(2, target);
            return request.data();
        }

        // ListenRequest{database = 1, remove_target = 3}.
        inline std::string remove_target(const std::string& database, std::int32_t target_id) {
            protobuf::writer request;
            request.bytes(1, database);
            request.integer(3, target_id);
            return request.data();
        }

        // GetDocumentRequest{name = 1}.
        inline std::string get_document(const std::string& name) {
            protobuf::writer request;
            request.bytes(1, name);
            return request.data();
        }

        // The percent-encoding x-goog-request-params wants for a database's name.
        inline std::string url_encode(std::string_view text) {
            std::string out;
            for (unsigned char c : text) {
                if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                    out += static_cast<char>(c);
                } else {
                    char hex[4];
                    std::snprintf(hex, sizeof hex, "%%%02X", c);
                    out += hex;
                }
            }
            return out;
        }

    }  // namespace firestore

    // ---------------------------------------------------------------------------
    // Firebase Auth: signing in, and an ID token kept fresh
    // ---------------------------------------------------------------------------

    struct user {
        std::string uid;
        std::map<std::string, value> claims;  // everything the ID token says, like a custom token's own claims
    };

    // Signs in with Identity Toolkit and keeps the ID token fresh with Secure Token,
    // both over REST. Safe to use from several threads.
    class auth {
    public:
        explicit auth(options o) : options_(std::move(o)) {}

        // A custom token, like the one a uione backend gives a service for its key.
        void sign_in_with_custom_token(const std::string& token) {
            std::string body = "{\"token\":";
            detail::append_escaped(body, token);
            body += ",\"returnSecureToken\":true}";
            take(post(options_.identity_toolkit() + "/v1/accounts:signInWithCustomToken", body), "idToken", "refreshToken", "expiresIn");
        }

        // An access token from a provider, like GitHub's from its device flow: provider_id
        // is "github.com" or "google.com".
        void sign_in_with_idp(const std::string& provider_id, const std::string& access_token) {
            std::string post_body = "access_token=" + detail::form_encode(access_token) + "&providerId=" + detail::form_encode(provider_id);
            std::string body = "{\"postBody\":";
            detail::append_escaped(body, post_body);
            body += ",\"requestUri\":\"http://localhost\",\"returnSecureToken\":true,\"returnIdpCredential\":true}";
            take(post(options_.identity_toolkit() + "/v1/accounts:signInWithIdp", body), "idToken", "refreshToken", "expiresIn");
        }

        // A refresh token kept from an earlier sign-in.
        void sign_in_with_refresh_token(const std::string& refresh_token) {
            std::lock_guard hold(lock_);
            refresh_locked(refresh_token);
        }

        void sign_out() {
            std::lock_guard hold(lock_);
            id_token_.clear();
            refresh_token_.clear();
            user_.reset();
            expires_ = {};
        }

        std::optional<user> current_user() const {
            std::lock_guard hold(lock_);
            return user_;
        }

        // An ID token good for at least five more minutes, refreshed when it wouldn't
        // be; empty when nobody is signed in.
        std::string id_token() {
            std::lock_guard hold(lock_);
            if (id_token_.empty()) return {};
            if (std::chrono::system_clock::now() + std::chrono::minutes(5) >= expires_) refresh_locked(refresh_token_);
            return id_token_;
        }

        std::string refresh_token() const {
            std::lock_guard hold(lock_);
            return refresh_token_;
        }

        // When the ID token in hand stops being good.
        std::chrono::system_clock::time_point expires_at() const {
            std::lock_guard hold(lock_);
            return expires_;
        }

        // Gets a new ID token now, as when a server said the one in hand is no good.
        void refresh() {
            std::lock_guard hold(lock_);
            if (!refresh_token_.empty()) refresh_locked(refresh_token_);
        }

    private:
        std::string key() const { return options_.api_key.empty() ? "any" : options_.api_key; }

        value post(const std::string& url, const std::string& body, const std::string& type = "application/json") {
            response r = https_post(url + "?key=" + detail::form_encode(key()), {{"Content-Type", type}}, body);
            value answer;
            try {
                answer = parse_json(r.body);
            } catch (const failure&) {
                throw failure(r.status, "Auth answered " + std::to_string(r.status) + " with something that isn't JSON");
            }
            if (r.status != 200) {
                std::string message = answer["error"]["message"].as_string();
                throw failure(r.status, "signing in failed: " + (message.empty() ? "HTTP " + std::to_string(r.status) : message));
            }
            return answer;
        }

        void take(const value& answer, const char* token, const char* refresh, const char* expires) {
            std::lock_guard hold(lock_);
            keep(answer[token].as_string(), answer[refresh].as_string(), answer[expires]);
        }

        void refresh_locked(const std::string& refresh_token) {
            if (refresh_token.empty()) throw failure(0, "there's no refresh token to sign in with");
            value answer = post(options_.secure_token() + "/v1/token",
                                "grant_type=refresh_token&refresh_token=" + detail::form_encode(refresh_token), "application/x-www-form-urlencoded");
            keep(answer["id_token"].as_string(), answer["refresh_token"].as_string(), answer["expires_in"]);
        }

        // Keeps a new ID token, and what it says: who, what else, and until when.
        void keep(const std::string& id_token, const std::string& refresh_token, const value& expires_in) {
            if (id_token.empty()) throw failure(0, "Auth gave no ID token");
            user signed_in;
            std::chrono::system_clock::time_point expires = std::chrono::system_clock::now() + std::chrono::hours(1);
            auto first = id_token.find('.');
            auto second = id_token.find('.', first + 1);
            if (first != std::string::npos && second != std::string::npos) {
                value claims = parse_json(detail::base64url_decode(std::string_view(id_token).substr(first + 1, second - first - 1)));
                signed_in.claims = claims.as_map();
                signed_in.uid = claims["user_id"].as_string();
                if (signed_in.uid.empty()) signed_in.uid = claims["sub"].as_string();
                if (std::int64_t exp = claims["exp"].as_integer(); exp > 0) expires = std::chrono::system_clock::time_point(std::chrono::seconds(exp));
            } else {
                // Not a JWT; trust what Auth said of how long it lasts.
                std::string seconds = expires_in.as_string();
                if (!seconds.empty()) expires = std::chrono::system_clock::now() + std::chrono::seconds(std::stoll(seconds));
            }
            id_token_ = id_token;
            if (!refresh_token.empty()) refresh_token_ = refresh_token;
            user_ = std::move(signed_in);
            expires_ = expires;
        }

        options options_;
        mutable std::mutex lock_;
        std::string id_token_, refresh_token_;
        std::optional<user> user_;
        std::chrono::system_clock::time_point expires_{};
    };

    // ---------------------------------------------------------------------------
    // Executors: where a listener's callbacks run
    // ---------------------------------------------------------------------------

    class executor {
    public:
        virtual ~executor() = default;
        virtual void post(std::function<void()>) = 0;
    };

    // A queue the program drains on its own thread, as a main loop does.
    class queue_executor : public executor {
    public:
        void post(std::function<void()> task) override {
            {
                std::lock_guard hold(lock_);
                tasks_.push_back(std::move(task));
            }
            ready_.notify_one();
        }

        // Runs everything queued, including what those tasks queue, then returns.
        void run_until_idle() {
            while (auto task = take(milliseconds(0))) (*task)();
        }

        // Runs one task, waiting up to `wait` for one. False when none came.
        bool run_one_for(milliseconds wait) {
            auto task = take(wait);
            if (!task) return false;
            (*task)();
            return true;
        }

    private:
        std::optional<std::function<void()>> take(milliseconds wait) {
            std::unique_lock hold(lock_);
            if (!ready_.wait_for(hold, wait, [&] { return !tasks_.empty(); })) return std::nullopt;
            auto task = std::move(tasks_.front());
            tasks_.pop_front();
            return task;
        }

        std::mutex lock_;
        std::condition_variable ready_;
        std::deque<std::function<void()>> tasks_;
    };

    // ---------------------------------------------------------------------------
    // The database: one live stream for every document listened to
    // ---------------------------------------------------------------------------

    namespace detail {

        // Opens HTTP/2 to Firestore, over TLS unless it's an emulator.
        inline std::unique_ptr<http2::connection> connect(const options::place& where) {
            std::unique_ptr<transport> link;
            if (where.secure) {
                link = std::make_unique<tls_transport>(where.host, where.port, std::vector<std::string>{"h2"});
                if (link->protocol() != "h2") throw connection_error("the server didn't agree to HTTP/2");
            } else {
                link = std::make_unique<plain_transport>(where.host, where.port);
            }
            return std::make_unique<http2::connection>(std::move(link));
        }

        inline std::vector<hpack::header> call_headers(const options& o, const options::place& where, const std::string& method, const std::string& token) {
            std::string database = o.database_name();
            std::vector<hpack::header> headers = {
                {":method", "POST"},
                {":scheme", where.secure ? "https" : "http"},
                {":path", "/google.firestore.v1.Firestore/" + method},
                {":authority", where.host},
                {"content-type", "application/grpc"},
                {"te", "trailers"},
                {"user-agent", "ember/" EMBER_VERSION},
                {"google-cloud-resource-prefix", database},
                {"x-goog-request-params", "database=" + firestore::url_encode(database)},
            };
            if (!token.empty()) headers.emplace_back("authorization", "Bearer " + token);
            return headers;
        }

        // Firestore's codes worth trying again after: cancelled, unknown, deadline
        // exceeded, resource exhausted, aborted, internal, unavailable, and
        // unauthenticated, after a new token.
        inline bool retryable(int code) {
            static constexpr int codes[] = {1, 2, 4, 8, 10, 13, 14, 16};
            return std::find(std::begin(codes), std::end(codes), code) != std::end(codes);
        }

    }  // namespace detail

    // Reads documents, once or live. Every listen shares one stream to Firestore, a
    // target each, as Google's own clients do: a document listened to twice is one
    // target told to both. A dropped connection is reopened with a growing wait, each
    // target resuming from where it stopped, so no change is missed and none is told
    // twice. The ID token is renewed before it runs out, and the stream with it.
    //
    // Callbacks run on the executor given, or on a thread of the database's own.
    class database {
        struct listening {
            std::uint64_t id;
            std::function<void(const snapshot&)> on_snapshot;
            std::function<void(const error&)> on_error;
            std::shared_ptr<std::atomic<bool>> active;
        };
        struct target {
            std::string path, name;
            std::int32_t id = 0;
            std::string resume_token;
            bool sent = false;     // asked for on the stream now open
            bool current = false;  // the server has said all there is, up to now
            bool told = false;     // a snapshot has been told
            std::optional<firestore::document> pending;  // as the server has said since the last consistent moment
            std::optional<firestore::document> known;    // as it was at that moment
            std::vector<listening> listeners;
        };
        struct core {
            options settings;
            auth* signed_in = nullptr;
            executor* deliver = nullptr;
            std::mutex lock;
            std::condition_variable wake;
            std::map<std::string, target> targets;  // by path
            std::vector<std::int32_t> removed;      // targets to take off the open stream
            std::int32_t next_target = 2;
            std::uint64_t next_listener = 1;
            std::atomic<bool> stopping{false};
            bool connected = false;
        };

    public:
        class registration {
        public:
            registration() = default;
            registration(std::weak_ptr<core> owner, std::string path, std::uint64_t id) : owner_(std::move(owner)), path_(std::move(path)), id_(id) {}
            registration(registration&& other) noexcept { *this = std::move(other); }
            registration& operator=(registration&& other) noexcept {
                if (this != &other) {
                    remove();
                    owner_ = std::move(other.owner_);
                    path_ = std::move(other.path_);
                    id_ = std::exchange(other.id_, 0);
                }
                return *this;
            }
            registration(const registration&) = delete;
            registration& operator=(const registration&) = delete;
            ~registration() { remove(); }

            // Stops listening: nothing more is told, even what's already queued.
            void remove() {
                if (id_ == 0) return;
                if (auto c = owner_.lock()) database::unlisten(*c, path_, id_);
                id_ = 0;
            }

        private:
            std::weak_ptr<core> owner_;
            std::string path_;
            std::uint64_t id_ = 0;
        };

        explicit database(options o, auth* signed_in = nullptr, executor* deliver_on = nullptr) : core_(std::make_shared<core>()) {
            core_->settings = std::move(o);
            core_->signed_in = signed_in;
            if (!deliver_on) {
                own_queue_ = std::make_unique<queue_executor>();
                deliver_on = own_queue_.get();
                delivering_ = std::thread([c = core_, queue = own_queue_.get()] {
                    while (!c->stopping) queue->run_one_for(milliseconds(100));
                });
            }
            core_->deliver = deliver_on;
            streaming_ = std::thread([c = core_] { run(c); });
        }

        ~database() {
            core_->stopping = true;
            core_->wake.notify_all();
            if (streaming_.joinable()) streaming_.join();
            if (delivering_.joinable()) delivering_.join();
        }

        database(const database&) = delete;
        database& operator=(const database&) = delete;

        // The document as it is now, read once. One that isn't there doesn't exist.
        snapshot get(const std::string& path) {
            const options& o = core_->settings;
            auto where = o.firestore();
            std::string name = o.database_name() + "/documents/" + path;
            auto connection = detail::connect(where);
            std::uint32_t stream = connection->open(detail::call_headers(o, where, "GetDocument", token(*core_, where)));
            connection->send(stream, grpc::frame_message(firestore::get_document(name)), true);
            grpc::messages incoming;
            std::optional<std::string> answer;
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
            for (;;) {
                if (std::chrono::steady_clock::now() > deadline) throw connection_error("no answer within a minute");
                auto e = connection->next(milliseconds(1000));
                if (!e || e->stream != stream) continue;
                if (e->type == http2::event::kind::reset) throw status_error(14, "the server reset the call");
                if (e->type == http2::event::kind::headers) {
                    try {
                        grpc::check(e->headers);
                    } catch (const status_error& refused) {
                        if (refused.code != 5) throw;  // not found: it doesn't exist
                        snapshot s;
                        s.path = path;
                        return s;
                    }
                } else {
                    incoming.add(e->data);
                    if (auto message = incoming.next()) answer = std::move(message);
                }
                if (e->ended) break;
            }
            snapshot s;
            s.path = path;
            if (answer) {
                auto d = firestore::read_document(*answer);
                s.exists = true;
                s.data = std::move(d.fields);
                s.update_time = d.update_time;
            }
            return s;
        }

        // Tells on_snapshot the document as it is, once the server has said all there
        // is, then each time it changes. on_error is told once if it can't be listened
        // to any more, as when the reader may no longer read it; then nothing more is.
        registration listen(const std::string& path, std::function<void(const snapshot&)> on_snapshot, std::function<void(const error&)> on_error = {}) {
            auto& c = *core_;
            std::lock_guard hold(c.lock);
            auto [it, made] = c.targets.try_emplace(path);
            target& t = it->second;
            if (made) {
                t.path = path;
                t.name = c.settings.database_name() + "/documents/" + path;
                t.id = c.next_target;
                c.next_target += 2;
            }
            listening l{c.next_listener++, std::move(on_snapshot), std::move(on_error), std::make_shared<std::atomic<bool>>(true)};
            // A document already known is told at once, as it is, to the new listener.
            if (t.told) tell(c, l, t, !c.connected);
            t.listeners.push_back(std::move(l));
            c.wake.notify_all();
            return registration(core_, path, t.listeners.back().id);
        }

    private:
        static constexpr milliseconds idle{30000};   // a quiet connection is pinged after this
        static constexpr milliseconds answer{10000};  // and taken as gone if it says nothing for this long

        static void say(core& c, const std::string& text) {
            if (c.settings.log) c.settings.log(text);
        }

        static std::string token(core& c, const options::place& where) {
            if (c.signed_in) {
                if (std::string t = c.signed_in->id_token(); !t.empty()) return t;
            }
            // The emulator lets "owner" past its rules, for a program that signs nobody in.
            return where.emulator ? "owner" : "";
        }

        static void unlisten(core& c, const std::string& path, std::uint64_t id) {
            std::lock_guard hold(c.lock);
            auto it = c.targets.find(path);
            if (it == c.targets.end()) return;
            auto& listeners = it->second.listeners;
            for (auto l = listeners.begin(); l != listeners.end(); ++l) {
                if (l->id == id) {
                    *l->active = false;
                    listeners.erase(l);
                    break;
                }
            }
            if (listeners.empty()) {
                if (it->second.sent) c.removed.push_back(it->second.id);
                c.targets.erase(it);
            }
        }

        static void tell(core& c, const listening& l, const target& t, bool from_cache) {
            snapshot s;
            s.path = t.path;
            s.from_cache = from_cache;
            s.exists = t.known.has_value();
            if (t.known) {
                s.data = t.known->fields;
                s.update_time = t.known->update_time;
            }
            c.deliver->post([active = l.active, call = l.on_snapshot, s = std::move(s)] {
                if (*active && call) call(s);
            });
        }

        static void fail(core& c, target& t, const error& e) {
            for (auto& l : t.listeners) {
                c.deliver->post([active = l.active, call = l.on_error, e] {
                    if (*active && call) call(e);
                });
                // Told once; nothing more reaches it.
                c.deliver->post([active = l.active] { *active = false; });
            }
        }

        static void run(std::shared_ptr<core> owner) {
            core& c = *owner;
            auto wait = std::chrono::seconds(1);
            std::mt19937 random{std::random_device{}()};
            while (!c.stopping) {
                {
                    std::unique_lock hold(c.lock);
                    c.wake.wait_for(hold, milliseconds(200), [&] { return c.stopping || !c.targets.empty(); });
                    if (c.stopping || c.targets.empty()) continue;
                }
                bool renew = false;
                try {
                    renew = stream_once(c);
                    wait = std::chrono::seconds(1);
                } catch (const status_error& e) {
                    if (!detail::retryable(e.code)) {
                        // Refused for good: every listener is told, and let go.
                        std::lock_guard hold(c.lock);
                        for (auto& [path, t] : c.targets) fail(c, t, {e.code, e.what()});
                        c.targets.clear();
                        c.removed.clear();
                    } else {
                        if (e.code == 16 && c.signed_in) {
                            try {
                                c.signed_in->refresh();
                            } catch (const std::exception&) {
                            }
                        }
                        say(c, "the stream ended (" + std::string(e.what()) + ")");
                    }
                } catch (const failure& e) {
                    say(c, std::string("the connection dropped: ") + e.what());
                } catch (const std::exception& e) {
                    say(c, std::string("the connection failed: ") + e.what());
                }
                {
                    // Whatever was asked for is asked again on the next stream, from where
                    // each left off.
                    std::lock_guard hold(c.lock);
                    c.connected = false;
                    c.removed.clear();
                    for (auto& [path, t] : c.targets) {
                        t.sent = false;
                        t.current = false;
                        t.pending = t.known;
                    }
                }
                if (c.stopping || renew) continue;
                std::uniform_int_distribution<int> jitter(0, static_cast<int>(wait.count()) * 500);
                auto pause = std::chrono::duration_cast<milliseconds>(wait) + milliseconds(jitter(random));
                say(c, "reconnecting in " + std::to_string(pause.count()) + " ms");
                for (auto until = std::chrono::steady_clock::now() + pause; !c.stopping && std::chrono::steady_clock::now() < until;) {
                    std::this_thread::sleep_for(milliseconds(50));
                }
                wait = std::min(wait * 2, std::chrono::seconds(60));
            }
        }

        // One stream, for as long as it lasts. True when it ended to start again with a
        // new token; false when there was nothing left to listen to.
        static bool stream_once(core& c) {
            auto where = c.settings.firestore();
            std::string database = c.settings.database_name();
            std::string bearer = token(c, where);
            auto renew_at = c.signed_in && !bearer.empty() && bearer != "owner"
                                ? c.signed_in->expires_at() - std::chrono::minutes(5)
                                : std::chrono::system_clock::time_point::max();
            auto connection = detail::connect(where);
            std::uint32_t stream = connection->open(detail::call_headers(c.settings, where, "Listen", bearer));
            {
                std::lock_guard hold(c.lock);
                c.connected = true;
            }
            say(c, "listening");
            grpc::messages incoming;
            bool pinged = false;
            while (!c.stopping) {
                {
                    // What was asked for or let go since, on the open stream.
                    std::lock_guard hold(c.lock);
                    if (c.targets.empty()) {
                        connection->reset(stream);
                        return false;
                    }
                    for (std::int32_t id : c.removed) connection->send(stream, grpc::frame_message(firestore::remove_target(database, id)), false);
                    c.removed.clear();
                    for (auto& [path, t] : c.targets) {
                        if (t.sent) continue;
                        connection->send(stream, grpc::frame_message(firestore::add_document_target(database, t.name, t.id, t.resume_token)), false);
                        t.sent = true;
                        say(c, t.resume_token.empty() ? "listening to " + path : "listening to " + path + " again, from where it stopped");
                    }
                }
                if (std::chrono::system_clock::now() >= renew_at) {
                    say(c, "renewing the sign-in");
                    connection->reset(stream);
                    return true;
                }
                auto e = connection->next(milliseconds(50));
                if (!e) {
                    auto quiet = std::chrono::steady_clock::now() - connection->last_heard();
                    if (!pinged && quiet > idle) {
                        connection->ping();
                        pinged = true;
                    } else if (pinged && quiet > idle + answer) {
                        throw connection_error("the server stopped answering");
                    }
                    continue;
                }
                pinged = false;
                if (e->stream != stream) continue;
                if (e->type == http2::event::kind::reset) throw status_error(14, "the server reset the stream (" + std::to_string(e->reset_code) + ")");
                if (e->type == http2::event::kind::headers) {
                    grpc::check(e->headers);
                    if (e->ended) throw status_error(14, "the server ended the stream");
                    continue;
                }
                incoming.add(e->data);
                while (auto message = incoming.next()) {
                    std::lock_guard hold(c.lock);
                    handle(c, *connection, stream, firestore::read_listen_response(*message));
                }
                if (e->ended) throw status_error(14, "the server ended the stream");
            }
            connection->reset(stream);
            return false;
        }

        static target* by_id(core& c, std::int32_t id) {
            for (auto& [path, t] : c.targets) {
                if (t.id == id && t.sent) return &t;
            }
            return nullptr;
        }

        // The targets a message names, or every one asked for when it names none.
        static std::vector<target*> named(core& c, const std::vector<std::int32_t>& ids) {
            std::vector<target*> out;
            if (ids.empty()) {
                for (auto& [path, t] : c.targets) {
                    if (t.sent) out.push_back(&t);
                }
            } else {
                for (auto id : ids) {
                    if (auto* t = by_id(c, id)) out.push_back(t);
                }
            }
            return out;
        }

        static void handle(core& c, http2::connection& connection, std::uint32_t stream, const firestore::listen_response& r) {
            using kind = firestore::listen_response::kind;
            switch (r.type) {
                case kind::target_change: {
                    auto ts = named(c, r.target_ids);
                    switch (r.change) {
                        case firestore::change_type::remove:
                            // The server let the target go: with a cause, it won't be
                            // listened to; its listeners are told, once, and let go.
                            if (r.cause_code != 0) {
                                for (auto* t : ts) {
                                    fail(c, *t, {r.cause_code, r.cause_message.empty() ? "the server stopped the listen" : r.cause_message});
                                    c.targets.erase(t->path);
                                }
                            }
                            return;
                        case firestore::change_type::current:
                            for (auto* t : ts) t->current = true;
                            break;
                        case firestore::change_type::reset:
                            // What the server said since the last consistent moment no
                            // longer stands; it says it again.
                            for (auto* t : ts) t->pending = t->known;
                            break;
                        default:
                            break;
                    }
                    if (!r.resume_token.empty()) {
                        for (auto* t : ts) t->resume_token = r.resume_token;
                    }
                    // No targets and a read time: a consistent moment for every target.
                    if (r.change == firestore::change_type::no_change && r.target_ids.empty() && r.read_time) {
                        for (auto& [path, t] : c.targets) {
                            if (t.sent && t.current) settle(c, t);
                        }
                    }
                    break;
                }
                case kind::document_change:
                    for (auto id : r.target_ids) {
                        if (auto* t = by_id(c, id); t && t->name == r.changed.name) t->pending = r.changed;
                    }
                    for (auto id : r.removed_target_ids) {
                        if (auto* t = by_id(c, id)) t->pending.reset();
                    }
                    break;
                case kind::document_delete:
                case kind::document_remove:
                    for (auto& [path, t] : c.targets) {
                        bool named_here = std::find(r.removed_target_ids.begin(), r.removed_target_ids.end(), t.id) != r.removed_target_ids.end();
                        if (t.sent && (named_here || (r.removed_target_ids.empty() && t.name == r.document_name))) t.pending.reset();
                    }
                    break;
                case kind::filter:
                    // The server's count of the target's documents. If ours differs, we
                    // missed something: listen to it afresh, under a new target.
                    for (auto id : r.target_ids) {
                        target* t = by_id(c, id);
                        if (!t || r.count == (t->pending ? 1 : 0)) continue;
                        connection.send(stream, grpc::frame_message(firestore::remove_target(c.settings.database_name(), t->id)), false);
                        t->id = c.next_target;
                        c.next_target += 2;
                        t->resume_token.clear();
                        t->current = false;
                        t->sent = false;
                        t->pending = t->known;
                    }
                    break;
                case kind::none:
                    break;
            }
        }

        // Tells every listener, the first time and then only when the document differs
        // from what was last told.
        static void settle(core& c, target& t) {
            bool same = t.told && t.pending.has_value() == t.known.has_value() && (!t.pending || t.pending->update_time == t.known->update_time);
            t.known = t.pending;
            if (same) return;
            t.told = true;
            for (const auto& l : t.listeners) tell(c, l, t, false);
        }

        std::shared_ptr<core> core_;
        std::unique_ptr<queue_executor> own_queue_;
        std::thread streaming_;
        std::thread delivering_;
    };

}  // namespace ember
