// http.hpp: tiny HTTP/1.1 server for the local GUI. Binds 127.0.0.1 only.
#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ds {

struct Request {
    std::string method, path, body;
    std::map<std::string, std::string> query, headers;  // header names lowercased

    std::string header(const std::string &k) const { auto it = headers.find(k); return it == headers.end() ? "" : it->second; }
    std::string param(const std::string &k, const std::string &def = "") const {
        auto it = query.find(k);
        return it == query.end() ? def : it->second;
    }
};

struct Response {
    int status = 200;
    std::string contentType = "application/json";
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
};

class HttpServer {
public:
    using Handler = std::function<Response(const Request &)>;
    bool listen(uint16_t port);  // 0 = any free port
    uint16_t port() const { return port_; }
    [[noreturn]] void run(Handler h);  // one thread per connection

private:
    int fd_ = -1;
    uint16_t port_ = 0;
};

} // namespace ds
