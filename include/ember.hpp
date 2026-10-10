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
// What it does today: listen to a document and be told, live, each time it changes.
// It follows Firestore's watch protocol: a target per listen, the server's resume
// token kept so a dropped connection picks up where it left off, and a snapshot only
// at the points the server says are consistent.
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
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
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

    // Anything that went wrong: a connection, the protocol, or the server saying no.
    struct error : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    // The connection itself failed: worth trying again.
    struct connection_error : error {
        using error::error;
    };

    // The server refused, with a gRPC status, like 7 for permission denied.
    struct status_error : error {
        status_error(int code, const std::string& message)
            : error(message.empty() ? "gRPC status " + std::to_string(code) : message), code(code) {}
        int code;
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

    // One field's value. A map keeps its fields in the order they're named, sorted, so
    // two equal documents print the same.
    struct value {
        enum class kind { null, boolean, integer, floating, time, string, bytes, reference, point, array, map };

        kind type = kind::null;
        bool boolean = false;
        std::int64_t integer = 0;
        double floating = 0;
        ember::timestamp time;
        std::string text;  // a string, bytes or a reference
        geo_point point;
        std::vector<value> items;
        std::vector<std::pair<std::string, value>> fields;

        const value* find(std::string_view name) const {
            for (const auto& [key, field] : fields) {
                if (key == name) return &field;
            }
            return nullptr;
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
                for (std::size_t i = 0; i < v.fields.size(); ++i) {
                    if (i) out += ',';
                    detail::append_escaped(out, v.fields[i].first);
                    out += ':';
                    to_json(v.fields[i].second, out);
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
                    if (at_ >= data_.size()) throw error("a protocol buffer ends inside a number");
                    auto byte = static_cast<std::uint8_t>(data_[at_++]);
                    n |= static_cast<std::uint64_t>(byte & 0x7f) << shift;
                    if (!(byte & 0x80)) return n;
                }
                throw error("a protocol buffer number is too long");
            }
            std::string_view bytes() {
                std::uint64_t length = varint();
                if (length > data_.size() - at_) throw error("a protocol buffer field runs past its end");
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
                    default: throw error("a protocol buffer field has an unknown wire type");
                }
            }

        private:
            std::uint64_t fixed(std::size_t size) {
                if (size > data_.size() - at_) throw error("a protocol buffer ends inside a number");
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
                    if (next < 0) throw error("a header has a Huffman code that doesn't exist");
                    at = static_cast<std::size_t>(next);
                    ++depth;
                    if (auto symbol = tree.nodes[at].symbol; symbol >= 0) {
                        if (symbol == 256) throw error("a header holds Huffman's end-of-string code");
                        out += static_cast<char>(symbol);
                        at = 0;
                        depth = 0;
                    }
                }
            }
            // What's left over is padding: at most seven bits, all ones, which is the
            // start of the end-of-string code.
            if (depth > 7) throw error("a header's Huffman padding is too long");
            return out;
        }

        inline std::uint64_t read_integer(std::string_view in, std::size_t& at, int prefix) {
            if (at >= in.size()) throw error("a header block ends early");
            std::uint64_t mask = (1u << prefix) - 1;
            std::uint64_t n = static_cast<std::uint8_t>(in[at++]) & mask;
            if (n < mask) return n;
            for (int shift = 0; shift < 63; shift += 7) {
                if (at >= in.size()) throw error("a header block ends inside a number");
                auto byte = static_cast<std::uint8_t>(in[at++]);
                n += static_cast<std::uint64_t>(byte & 0x7f) << shift;
                if (!(byte & 0x80)) return n;
            }
            throw error("a header block's number is too long");
        }

        inline std::string read_string(std::string_view in, std::size_t& at) {
            if (at >= in.size()) throw error("a header block ends early");
            bool huffman = static_cast<std::uint8_t>(in[at]) & 0x80;
            std::uint64_t length = read_integer(in, at, 7);
            if (length > in.size() - at) throw error("a header's text runs past the block");
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
                        if (size > limit_) throw error("the peer grew the header table past what we allowed");
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
                if (index == 0) throw error("a header names table entry 0");
                if (index < 62) return {std::string(static_table[index].first), std::string(static_table[index].second)};
                std::uint64_t dynamic = index - 62;
                if (dynamic >= table_.size()) throw error("a header names a table entry that doesn't exist");
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
                    if (p.empty()) throw error("a padded frame has no padding length");
                    pad = std::uint8_t(p[0]);
                    p.remove_prefix(1);
                }
                if (f.type == headers_frame && (f.flags & priority)) {
                    if (p.size() < 5) throw error("a HEADERS frame's priority is cut short");
                    p.remove_prefix(5);
                }
                if (pad > p.size()) throw error("a frame's padding is longer than the frame");
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
                        throw error("the server pushed, which we turned off");
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
                            if (f.stream != block_stream_) throw error("a CONTINUATION frame is on the wrong stream");
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
                if (buffer_[0] != 0) throw error("the server compressed a message, which we didn't ask for");
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
    // Firestore
    // ---------------------------------------------------------------------------

    // Where Firestore is and who's asking.
    struct options {
        std::string project;
        std::string database = "(default)";
        std::string host = "firestore.googleapis.com";
        std::string port = "443";
        bool secure = true;
        // The bearer token for each new connection, like a Firebase ID token; empty when
        // nobody is signed in. Asked again on every reconnect, so it can be refreshed.
        std::function<std::string()> token;
        // Where the client says what it's doing, like reconnecting. Quiet when empty.
        std::function<void(std::string_view)> log;

        // For the project, or for the emulator when FIRESTORE_EMULATOR_HOST is set: then
        // plain HTTP/2, and "owner", which the emulator lets past its rules.
        static options for_project(std::string project) {
            options o;
            o.project = std::move(project);
            if (const char* emulator = std::getenv("FIRESTORE_EMULATOR_HOST"); emulator && *emulator) {
                std::string_view where = emulator;
                auto colon = where.rfind(':');
                o.host = std::string(where.substr(0, colon));
                o.port = colon == std::string_view::npos ? "8080" : std::string(where.substr(colon + 1));
                o.secure = false;
                o.token = [] { return std::string("owner"); };
            }
            return o;
        }

        std::string database_name() const { return "projects/" + project + "/databases/" + database; }
    };

    // A document as it was at one consistent moment.
    struct snapshot {
        std::string path;  // like views/projects::issue_page:neotrac-42
        bool exists = false;
        value data;  // its fields, as a map
        timestamp update_time;
        bool from_cache = false;
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

        inline void sort_fields(value& map) {
            std::sort(map.fields.begin(), map.fields.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
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
                            if (f == 1 && t == protobuf::length_wire) v.fields.push_back(read_entry(map.bytes()));
                            else map.skip(t);
                        }
                        sort_fields(v);
                        break;
                    }
                    default: in.skip(type);
                }
            }
            return v;
        }

        inline value map_value() {
            value v;
            v.type = value::kind::map;
            return v;
        }

        struct document {
            std::string name;
            value fields = map_value();
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
                else if (field == 2 && type == protobuf::length_wire) d.fields.fields.push_back(read_entry(in.bytes()));
                else if (field == 3 && type == protobuf::length_wire) d.create_time = read_timestamp(in.bytes());
                else if (field == 4 && type == protobuf::length_wire) d.update_time = read_timestamp(in.bytes());
                else in.skip(type);
            }
            sort_fields(d.fields);
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

    // Listens to one document, telling `changed` each time it's different at a moment
    // the server says is consistent, the first time included, whether or not it exists.
    //
    // run() blocks, reconnecting after a dropped connection with a growing wait and
    // resuming from the server's last resume token, so no change is missed and none is
    // told twice. It returns after stop(), or throws when the server refuses for good,
    // as when the reader isn't allowed to read the document.
    class listener {
    public:
        listener(options o, std::string path, std::function<void(const snapshot&)> changed)
            : options_(std::move(o)), path_(std::move(path)), changed_(std::move(changed)) {
            name_ = options_.database_name() + "/documents/" + path_;
        }

        // Safe from another thread, or a signal: run() returns within a second.
        void stop() { stopping_ = true; }

        void run() {
            auto wait = std::chrono::seconds(1);
            std::mt19937 random{std::random_device{}()};
            while (!stopping_) {
                try {
                    listen_once();
                    wait = std::chrono::seconds(1);
                } catch (const status_error& e) {
                    // Firestore's retryable codes: cancelled, unknown, deadline exceeded,
                    // resource exhausted, internal, unavailable, unauthenticated (a token
                    // that expired, asked anew on the next connection).
                    static constexpr int retryable[] = {1, 2, 4, 8, 13, 14, 16};
                    if (std::find(std::begin(retryable), std::end(retryable), e.code) == std::end(retryable)) throw;
                    say("the stream ended (" + std::string(e.what()) + ")");
                } catch (const connection_error& e) {
                    say(std::string("the connection dropped: ") + e.what());
                }
                if (stopping_) break;
                // Up to a minute between tries, with jitter so many clients don't
                // return at once.
                std::uniform_int_distribution<int> jitter(0, static_cast<int>(wait.count()) * 500);
                auto pause = std::chrono::duration_cast<milliseconds>(wait) + milliseconds(jitter(random));
                say("reconnecting in " + std::to_string(pause.count()) + " ms");
                for (auto until = std::chrono::steady_clock::now() + pause; !stopping_ && std::chrono::steady_clock::now() < until;) {
                    std::this_thread::sleep_for(milliseconds(50));
                }
                wait = std::min(wait * 2, std::chrono::seconds(60));
            }
        }

    private:
        static constexpr std::int32_t target_id = 1;
        // How long a quiet connection waits before we ping it, and how long after that
        // a silent one is taken as gone.
        static constexpr milliseconds idle{30000};
        static constexpr milliseconds answer{10000};

        void say(const std::string& text) {
            if (options_.log) options_.log(text);
        }

        void listen_once() {
            std::unique_ptr<transport> link;
            if (options_.secure) {
                link = std::make_unique<tls_transport>(options_.host, options_.port, std::vector<std::string>{"h2"});
                if (link->protocol() != "h2") throw connection_error("the server didn't agree to HTTP/2");
            } else {
                link = std::make_unique<plain_transport>(options_.host, options_.port);
            }
            http2::connection connection(std::move(link));

            std::string database = options_.database_name();
            std::vector<hpack::header> headers = {
                {":method", "POST"},
                {":scheme", options_.secure ? "https" : "http"},
                {":path", "/google.firestore.v1.Firestore/Listen"},
                {":authority", options_.host},
                {"content-type", "application/grpc"},
                {"te", "trailers"},
                {"user-agent", "ember/0.1"},
                {"google-cloud-resource-prefix", database},
                {"x-goog-request-params", "database=" + firestore::url_encode(database)},
            };
            if (options_.token) {
                if (std::string token = options_.token(); !token.empty()) headers.emplace_back("authorization", "Bearer " + token);
            }
            std::uint32_t stream = connection.open(headers);
            connection.send(stream, grpc::frame_message(firestore::add_document_target(database, name_, target_id, resume_token_)), false);
            say(resume_token_.empty() ? "listening to " + path_ : "listening to " + path_ + " again, from where it stopped");

            grpc::messages incoming;
            bool pinged = false;
            while (!stopping_) {
                auto e = connection.next(milliseconds(1000));
                if (!e) {
                    auto quiet = std::chrono::steady_clock::now() - connection.last_heard();
                    if (!pinged && quiet > idle) {
                        connection.ping();
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
                while (auto message = incoming.next()) handle(firestore::read_listen_response(*message));
                if (e->ended) throw status_error(14, "the server ended the stream");
            }
            connection.reset(stream);
        }

        bool ours(const std::vector<std::int32_t>& ids) const {
            return std::find(ids.begin(), ids.end(), target_id) != ids.end();
        }

        void handle(const firestore::listen_response& r) {
            using kind = firestore::listen_response::kind;
            switch (r.type) {
                case kind::target_change:
                    switch (r.change) {
                        case firestore::change_type::remove:
                            if (r.target_ids.empty() || ours(r.target_ids)) {
                                throw status_error(r.cause_code ? r.cause_code : 2, r.cause_message.empty() ? "the server stopped the listen" : r.cause_message);
                            }
                            break;
                        case firestore::change_type::current:
                            if (r.target_ids.empty() || ours(r.target_ids)) current_ = true;
                            break;
                        case firestore::change_type::reset:
                            // What the server said about the document since the last
                            // consistent moment no longer stands; it says it again.
                            if (r.target_ids.empty() || ours(r.target_ids)) pending_ = known_;
                            break;
                        default:
                            break;
                    }
                    if (!r.resume_token.empty() && (r.target_ids.empty() || ours(r.target_ids))) resume_token_ = r.resume_token;
                    // A change with no targets and a read time is a consistent moment for
                    // every target: what's pending is now true.
                    if (r.change == firestore::change_type::no_change && r.target_ids.empty() && r.read_time && current_) settle();
                    break;
                case kind::document_change:
                    if (ours(r.target_ids)) pending_ = r.changed;
                    else if (ours(r.removed_target_ids)) pending_.reset();
                    break;
                case kind::document_delete:
                case kind::document_remove:
                    if (ours(r.removed_target_ids) || r.removed_target_ids.empty()) pending_.reset();
                    break;
                case kind::filter:
                    // The server's count of documents in the target. If ours differs, we
                    // missed something: forget the resume token and listen afresh.
                    if (ours(r.target_ids) && r.count != (pending_ ? 1 : 0)) {
                        resume_token_.clear();
                        current_ = false;
                        throw status_error(14, "the document's existence disagreed with the server's; listening afresh");
                    }
                    break;
                case kind::none:
                    break;
            }
        }

        // Tells `changed`, once for the first consistent moment and then only when the
        // document is different from what was last told.
        void settle() {
            bool same = told_ && pending_.has_value() == known_.has_value() &&
                        (!pending_ || pending_->update_time == known_->update_time);
            known_ = pending_;
            if (same) return;
            told_ = true;
            snapshot s;
            s.path = path_;
            s.exists = known_.has_value();
            if (known_) {
                s.data = known_->fields;
                s.update_time = known_->update_time;
            } else {
                s.data.type = value::kind::map;
            }
            changed_(s);
        }

        options options_;
        std::string path_;
        std::string name_;
        std::function<void(const snapshot&)> changed_;
        std::atomic<bool> stopping_{false};
        std::string resume_token_;
        bool current_ = false;
        bool told_ = false;
        std::optional<firestore::document> pending_;  // as the server has said since the last consistent moment
        std::optional<firestore::document> known_;    // as it was at that moment
    };
}  // namespace ember
