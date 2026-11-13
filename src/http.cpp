// http.cpp: minimal HTTP/1.1 (one request per connection, Connection: close).
#include "http.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace ds {
namespace {

constexpr size_t kMaxHeader = 64 * 1024, kMaxBody = 8 * 1024 * 1024;

std::string urlDecode(const std::string &s) {
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '+') out += ' ';
        else if (s[i] == '%' && i + 2 < s.size() && isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2])) {
            out += (char)std::stoi(s.substr(i + 1, 2), nullptr, 16);
            i += 2;
        } else out += s[i];
    }
    return out;
}

const char *reason(int s) {
    switch (s) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    default: return "Internal Server Error";
    }
}

bool sendAll(int fd, const std::string &s) {
    for (size_t off = 0; off < s.size();) {
        ssize_t n = send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
        if (n <= 0) return false;
        off += n;
    }
    return true;
}

void reply(int fd, const Response &r) {
    std::string h = "HTTP/1.1 " + std::to_string(r.status) + " " + reason(r.status) + "\r\nContent-Type: " +
                    r.contentType + "\r\nContent-Length: " + std::to_string(r.body.size()) +
                    "\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
                    "Referrer-Policy: no-referrer\r\n";
    for (auto &kv : r.headers) h += kv.first + ": " + kv.second + "\r\n";
    sendAll(fd, h + "\r\n" + r.body);
}

void serveConnection(int fd, const HttpServer::Handler &handler) {
    timeval tv{15, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    std::string buf;
    char chunk[16384];
    size_t headerEnd;
    while ((headerEnd = buf.find("\r\n\r\n")) == std::string::npos) {
        if (buf.size() > kMaxHeader) return reply(fd, {413, "text/plain", "header too large", {}});
        ssize_t n = recv(fd, chunk, sizeof chunk, 0);
        if (n <= 0) return;
        buf.append(chunk, n);
    }
    Request rq;
    size_t lineEnd = buf.find("\r\n");
    std::string line = buf.substr(0, lineEnd), target;
    size_t sp1 = line.find(' '), sp2 = line.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) return reply(fd, {400, "text/plain", "bad request", {}});
    rq.method = line.substr(0, sp1);
    target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    for (size_t pos = lineEnd + 2; pos < headerEnd;) {
        size_t e = buf.find("\r\n", pos), colon = buf.find(':', pos);
        if (colon != std::string::npos && colon < e) {
            std::string k = buf.substr(pos, colon - pos), v = buf.substr(colon + 1, e - colon - 1);
            for (char &c : k) c = (char)tolower((unsigned char)c);
            size_t b = v.find_first_not_of(" \t");
            rq.headers[k] = b == std::string::npos ? "" : v.substr(b);
        }
        pos = e + 2;
    }
    size_t q = target.find('?');
    rq.path = urlDecode(target.substr(0, q));
    if (q != std::string::npos) {
        std::string qs = target.substr(q + 1);
        for (size_t pos = 0; pos <= qs.size();) {
            size_t amp = qs.find('&', pos);
            if (amp == std::string::npos) amp = qs.size();
            std::string kv = qs.substr(pos, amp - pos);
            size_t eq = kv.find('=');
            if (!kv.empty()) rq.query[urlDecode(kv.substr(0, eq))] = eq == std::string::npos ? "" : urlDecode(kv.substr(eq + 1));
            pos = amp + 1;
        }
    }
    size_t len = strtoull(rq.header("content-length").c_str(), nullptr, 10);
    if (len > kMaxBody) return reply(fd, {413, "text/plain", "body too large", {}});
    rq.body = buf.substr(headerEnd + 4);
    while (rq.body.size() < len) {
        ssize_t n = recv(fd, chunk, sizeof chunk, 0);
        if (n <= 0) return;
        rq.body.append(chunk, n);
    }
    rq.body.resize(len);
    Response r;
    try {
        r = handler(rq);
    } catch (...) {
        r = {500, "application/json", std::string("{\"error\":\"internal error\"}"), {}};
    }
    reply(fd, r);
}

} // namespace

bool HttpServer::listen(uint16_t port) {
    fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) return false;
    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd_, (sockaddr *)&a, sizeof a) != 0 || ::listen(fd_, 64) != 0) return false;
    socklen_t al = sizeof a;
    getsockname(fd_, (sockaddr *)&a, &al);
    port_ = ntohs(a.sin_port);
    return true;
}

void HttpServer::run(Handler h) {
    for (;;) {
        int c = accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (c < 0) continue;
        std::thread([c, h] {
            serveConnection(c, h);
            close(c);
        }).detach();
    }
}

} // namespace ds
