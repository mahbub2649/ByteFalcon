// json.hpp: minimal JSON writer and parser (request bodies are small and simple).
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace ds {

class JsonWriter {
public:
    JsonWriter &beginObj() { sep(); s_ += '{'; first_.push_back(true); return *this; }
    JsonWriter &endObj() { s_ += '}'; first_.pop_back(); return *this; }
    JsonWriter &beginArr() { sep(); s_ += '['; first_.push_back(true); return *this; }
    JsonWriter &endArr() { s_ += ']'; first_.pop_back(); return *this; }
    JsonWriter &key(const char *k) { sep(); quote(k); s_ += ':'; afterKey_ = true; return *this; }

    JsonWriter &val(const std::string &v) { sep(); quote(v.c_str(), v.size()); return *this; }
    JsonWriter &val(const char *v) { sep(); quote(v); return *this; }
    JsonWriter &val(bool v) { sep(); s_ += v ? "true" : "false"; return *this; }
    JsonWriter &val(double v) { sep(); char b[32]; snprintf(b, sizeof b, "%.3f", v); s_ += b; return *this; }
    JsonWriter &val(int64_t v) { sep(); s_ += std::to_string(v); return *this; }
    JsonWriter &val(uint64_t v) { sep(); s_ += std::to_string(v); return *this; }
    JsonWriter &val(uint32_t v) { return val((uint64_t)v); }
    JsonWriter &val(int v) { return val((int64_t)v); }
    template <class T> JsonWriter &kv(const char *k, const T &v) { key(k); return val(v); }

    const std::string &str() const { return s_; }

private:
    void sep() {
        if (afterKey_) { afterKey_ = false; return; }
        if (!first_.empty()) {
            if (!first_.back()) s_ += ',';
            first_.back() = false;
        }
    }
    void quote(const char *p) { quote(p, strlen_(p)); }
    void quote(const char *p, size_t n) {
        s_ += '"';
        for (size_t i = 0; i < n; i++) {
            unsigned char c = p[i];
            if (c == '"') s_ += "\\\"";
            else if (c == '\\') s_ += "\\\\";
            else if (c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); s_ += b; }
            else s_ += (char)c;  // UTF-8 passes through; invalid bytes become U+FFFD in the browser
        }
        s_ += '"';
    }
    static size_t strlen_(const char *p) { size_t n = 0; while (p[n]) n++; return n; }

    std::string s_;
    std::vector<bool> first_;
    bool afterKey_ = false;
};

struct Json {
    enum Type { Null, Bool, Num, Str, Arr, Obj } type = Null;
    bool b = false;
    double n = 0;
    std::string s;
    std::vector<Json> a;
    std::vector<std::pair<std::string, Json>> o;

    const Json &operator[](const char *k) const {
        static const Json none;
        for (auto &kv : o)
            if (kv.first == k) return kv.second;
        return none;
    }
    double num(double def = 0) const { return type == Num ? n : def; }
    std::string str(const std::string &def = "") const { return type == Str ? s : def; }
    bool boolean(bool def = false) const { return type == Bool ? b : def; }

    static bool parse(const std::string &text, Json &out) {
        Parser p{text};
        try {
            if (!p.value(out)) return false;
            p.ws();
            return p.i == text.size();
        } catch (...) {
            return false;
        }
    }

private:
    struct Parser {
        const std::string &t;
        size_t i = 0;
        int depth = 0;

        void ws() { while (i < t.size() && (t[i] == ' ' || t[i] == '\n' || t[i] == '\r' || t[i] == '\t')) i++; }
        bool lit(const char *w, size_t n) { if (t.compare(i, n, w) != 0) return false; i += n; return true; }
        bool value(Json &v) {
            ws();
            if (i >= t.size() || ++depth > 64) return false;
            bool ok;
            char c = t[i];
            if (c == '{') ok = object(v);
            else if (c == '[') ok = array(v);
            else if (c == '"') { v.type = Str; ok = string(v.s); }
            else if (c == 't') { v.type = Bool; v.b = true; ok = lit("true", 4); }
            else if (c == 'f') { v.type = Bool; ok = lit("false", 5); }
            else if (c == 'n') ok = lit("null", 4);
            else ok = number(v);
            depth--;
            return ok;
        }
        bool number(Json &v) {
            const char *start = t.c_str() + i;
            char *end;
            v.n = strtod(start, &end);
            if (end == start) return false;
            v.type = Num;
            i += end - start;
            return true;
        }
        static void utf8(std::string &out, unsigned cp) {
            if (cp < 0x80) out += (char)cp;
            else if (cp < 0x800) { out += (char)(0xC0 | cp >> 6); out += (char)(0x80 | (cp & 63)); }
            else if (cp < 0x10000) { out += (char)(0xE0 | cp >> 12); out += (char)(0x80 | ((cp >> 6) & 63)); out += (char)(0x80 | (cp & 63)); }
            else { out += (char)(0xF0 | cp >> 18); out += (char)(0x80 | ((cp >> 12) & 63)); out += (char)(0x80 | ((cp >> 6) & 63)); out += (char)(0x80 | (cp & 63)); }
        }
        bool string(std::string &out) {
            i++;
            while (i < t.size()) {
                char c = t[i++];
                if (c == '"') return true;
                if (c != '\\') { out += c; continue; }
                if (i >= t.size()) return false;
                char e = t[i++];
                switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    if (i + 4 > t.size()) return false;
                    unsigned cp = std::stoul(t.substr(i, 4), nullptr, 16);
                    i += 4;
                    if (cp >= 0xD800 && cp <= 0xDBFF && t.compare(i, 2, "\\u") == 0 && i + 6 <= t.size()) {
                        unsigned lo = std::stoul(t.substr(i + 2, 4), nullptr, 16);
                        i += 6;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    utf8(out, cp);
                    break;
                }
                default: return false;
                }
            }
            return false;
        }
        bool array(Json &v) {
            v.type = Arr;
            i++;
            ws();
            if (i < t.size() && t[i] == ']') { i++; return true; }
            for (;;) {
                Json e;
                if (!value(e)) return false;
                v.a.push_back(std::move(e));
                ws();
                if (i < t.size() && t[i] == ',') { i++; continue; }
                if (i < t.size() && t[i] == ']') { i++; return true; }
                return false;
            }
        }
        bool object(Json &v) {
            v.type = Obj;
            i++;
            ws();
            if (i < t.size() && t[i] == '}') { i++; return true; }
            for (;;) {
                ws();
                std::string k;
                if (i >= t.size() || t[i] != '"' || !string(k)) return false;
                ws();
                if (i >= t.size() || t[i] != ':') return false;
                i++;
                Json e;
                if (!value(e)) return false;
                v.o.emplace_back(std::move(k), std::move(e));
                ws();
                if (i < t.size() && t[i] == ',') { i++; continue; }
                if (i < t.size() && t[i] == '}') { i++; return true; }
                return false;
            }
        }
    };
};

} // namespace ds
