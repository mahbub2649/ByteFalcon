// main.cpp: diskscan entry point.
//   GUI : serves the embedded web UI on 127.0.0.1 and opens it as an app window.
//   CLI : --cli prints a report in the terminal (also handy for benchmarking).
//
// Security: the server only listens on loopback, checks the Host header (blocks DNS
// rebinding) and requires a random per-run token on every API call (blocks other web
// pages and other local users from triggering deletions).
#include "cleaner.hpp"
#include "dupes.hpp"
#include "http.hpp"
#include "json.hpp"
#include "scanner.hpp"
#include "smart.hpp"
#include <chrono>
#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <mntent.h>
#include <pwd.h>
#include <queue>
#include <shared_mutex>
#include <spawn.h>
#include <sys/statvfs.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

extern char **environ;
using namespace ds;

namespace {

const char kUiHtml[] =
#include "ui_html.inc"
    ;
const char *kVersion = "1.0";

int64_t nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string homeDir() {
    const char *h = getenv("HOME");
    if (h && *h) return h;
    passwd *pw = getpwuid(getuid());
    return pw ? pw->pw_dir : "/";
}

std::string randomToken() {
    unsigned char b[16];
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, b, sizeof b) != (ssize_t)sizeof b) {
        perror("/dev/urandom");
        exit(1);
    }
    close(fd);
    static const char *hex = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += hex[c >> 4]; s += hex[c & 15]; }
    return s;
}

void spawnQuiet(const std::vector<std::string> &args) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    std::vector<char *> argv;
    for (auto &a : args) argv.push_back(const_cast<char *>(a.c_str()));
    argv.push_back(nullptr);
    pid_t pid;
    posix_spawnp(&pid, argv[0], &fa, nullptr, argv.data(), environ);  // reaped via SIGCHLD=SIG_IGN
    posix_spawn_file_actions_destroy(&fa);
}

bool inPath(const std::string &bin) {
    const char *p = getenv("PATH");
    std::string paths = p ? p : "/usr/bin:/bin";
    for (size_t s = 0; s <= paths.size();) {
        size_t e = paths.find(':', s);
        if (e == std::string::npos) e = paths.size();
        if (access((paths.substr(s, e - s) + "/" + bin).c_str(), X_OK) == 0) return true;
        s = e + 1;
    }
    return false;
}

// A Chromium-based browser in --app mode gives a frameless, native-looking window.
void openWindow(const std::string &url) {
    for (const char *b : {"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "microsoft-edge"})
        if (inPath(b)) return spawnQuiet({b, "--app=" + url, "--window-size=1360,880"});
    spawnQuiet({"xdg-open", url});
}

std::string human(uint64_t b) {
    const char *u[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double v = (double)b;
    int i = 0;
    while (v >= 1000 && i < 5) { v /= 1000; i++; }
    char buf[32];
    snprintf(buf, sizeof buf, i ? "%.1f %s" : "%.0f %s", v, u[i]);
    return buf;
}

const char *typeName(uint8_t t) { return t == T_DIR ? "d" : t == T_FILE ? "f" : t == T_LINK ? "l" : "o"; }

std::vector<uint32_t> sortedChildren(const Tree &t, uint32_t id) {
    std::vector<uint32_t> v;
    t.forEachChild(id, [&](uint32_t c) { v.push_back(c); });
    std::sort(v.begin(), v.end(), [&](uint32_t a, uint32_t b) { return t.nodes[a].size > t.nodes[b].size; });
    return v;
}

uint64_t toU64(const std::string &s, uint64_t def) {
    if (s.empty()) return def;
    char *e;
    unsigned long long v = strtoull(s.c_str(), &e, 10);
    return *e ? def : v;
}

void nodeFields(JsonWriter &w, const Tree &t, uint32_t id) {
    const Node &n = t.nodes[id];
    w.kv("id", id).kv("name", n.name).kv("type", typeName(n.type)).kv("size", n.size).kv("bytes", n.bytes).kv("mtime", n.mtime);
    if (n.type == T_DIR) w.kv("files", n.files).kv("hasKids", n.firstChild != kNone);
    if (n.flags & F_MOUNT) w.kv("mount", true);
    if (n.flags & F_HARDLINK) w.kv("hardlink", true);
    if (n.flags & F_ERROR) w.kv("unreadable", true);
}

void writeTree(JsonWriter &w, const Tree &t, uint32_t id, int depth, size_t limit, size_t subLimit) {
    w.beginObj();
    nodeFields(w, t, id);
    if (depth > 0 && t.nodes[id].type == T_DIR) {
        auto kids = sortedChildren(t, id);
        size_t n = std::min(kids.size(), limit);
        uint64_t rest = 0;
        for (size_t i = n; i < kids.size(); i++) rest += t.nodes[kids[i]].size;
        w.kv("restSize", rest).kv("restCount", (uint64_t)(kids.size() - n)).key("children").beginArr();
        for (size_t i = 0; i < n; i++) writeTree(w, t, kids[i], depth - 1, subLimit, subLimit);
        w.endArr();
    }
    w.endObj();
}

std::string extOf(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot || dot == name || !dot[1] || strlen(dot + 1) > 8) return "";
    std::string e(dot + 1);
    for (char &c : e) c = (char)tolower((unsigned char)c);
    return e;
}

Response jsonResponse(const JsonWriter &w) {
    Response r;
    r.body = w.str();
    return r;
}

Response errorResponse(int status, const std::string &msg) {
    JsonWriter w;
    w.beginObj().kv("error", msg).endObj();
    Response r = jsonResponse(w);
    r.status = status;
    return r;
}

class App {
public:
    App(std::string home, std::string token) : home_(std::move(home)), token_(std::move(token)) {}

    uint16_t port = 0;
    std::atomic<int64_t> lastPing{0}, byeAt{0};

    const std::string &token() const { return token_; }

    bool busy() {
        auto d = dupes();
        return scanning_ || (d && d->state == 1);
    }

    bool startScan(const std::string &path, unsigned threads, bool crossFs) {
        std::lock_guard<std::mutex> cl(cleanMu_);  // never swap the tree under a running cleanup
        std::lock_guard<std::mutex> jl(jobMu_);
        if (scanning_) return false;
        stopDupesLocked();
        if (scanThread_.joinable()) scanThread_.join();
        auto prog = std::make_shared<ScanProgress>();
        prog->running = true;
        {
            std::lock_guard<std::mutex> pl(progMu_);
            progress_ = prog;
        }
        scanning_ = true;
        ScanOptions opt{path, threads, crossFs};
        scanThread_ = std::thread([this, prog, opt] {
            auto t = scanTree(opt, *prog);
            if (t) {
                std::unique_lock<std::shared_mutex> tl(treeMu_);
                tree_ = std::move(t);
            }
            prog->running = false;
            scanning_ = false;
        });
        return true;
    }

    Response handle(const Request &rq) {
        std::string p = std::to_string(port), host = rq.header("host");
        if (host != "127.0.0.1:" + p && host != "localhost:" + p) return errorResponse(403, "bad host");
        if (rq.path == "/" || rq.path == "/index.html") {
            Response r;
            r.contentType = "text/html; charset=utf-8";
            r.body = kUiHtml;
            r.headers.push_back({"Content-Security-Policy",
                                 "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                                 "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"});
            return r;
        }
        if (rq.path.rfind("/api/", 0) != 0) return errorResponse(404, "not found");
        if (rq.header("x-token") != token_) return errorResponse(401, "bad token");
        Json body;
        if (!rq.body.empty() && !Json::parse(rq.body, body)) return errorResponse(400, "bad json");
        lastPing = nowMs();
        std::string ep = rq.path.substr(5);
        bool post = rq.method == "POST";

        if (ep == "info") return info();
        if (ep == "progress") return progress();
        if (ep == "scan" && post) {
            std::string path = body["path"].str(home_);
            if (path == "~" || path.rfind("~/", 0) == 0) path = home_ + path.substr(1);
            if (!startScan(path, (unsigned)body["threads"].num(0), body["crossFs"].boolean(false)))
                return errorResponse(409, "a scan is already running");
            return progress();
        }
        if (ep == "cancel" && post) {
            std::lock_guard<std::mutex> pl(progMu_);
            if (progress_) progress_->cancel = true;
            return errorResponse(200, "cancelling");
        }
        if (ep == "ping") return errorResponse(200, "ok");
        if (ep == "bye" && post) {
            byeAt = nowMs();
            return errorResponse(200, "bye");
        }
        if (ep == "dupes/start" && post) return dupesStart(body);
        if (ep == "dupes") return dupesStatus();
        if (ep == "clean" && post) return clean(body);

        std::shared_lock<std::shared_mutex> lk(treeMu_);
        if (!tree_) return errorResponse(409, "no scan yet");
        const Tree &t = *tree_;
        if (ep == "summary") return summary(t);
        if (ep == "node") return node(t, rq);
        if (ep == "tree") return tree(t, rq);
        if (ep == "largest") return topFiles(t, rq, false);
        if (ep == "old") return topFiles(t, rq, true);
        if (ep == "types") return types(t);
        if (ep == "smart") return smart(t);
        if (ep == "open" && post) return open(t, body);
        return errorResponse(404, "unknown endpoint");
    }

private:
    std::string display(const std::string &path) const {
        if (path == home_) return "~";
        if (path.size() > home_.size() && path.compare(0, home_.size(), home_) == 0 && path[home_.size()] == '/')
            return "~" + path.substr(home_.size());
        return path;
    }

    std::shared_ptr<DupeJob> dupes() {
        std::lock_guard<std::mutex> jl(jobMu_);
        return dupes_;
    }
    void stopDupesLocked() {
        if (dupes_) dupes_->cancel = true;
        if (dupeThread_.joinable()) dupeThread_.join();
        dupes_.reset();
    }

    Response info() {
        bool scanned;
        {
            std::shared_lock<std::shared_mutex> lk(treeMu_);
            scanned = tree_ != nullptr;
        }
        JsonWriter w;
        w.beginObj().kv("version", kVersion).kv("home", home_).kv("threads", defaultScanThreads()).kv("scanned", scanned);
        w.key("mounts").beginArr();
        static const std::unordered_set<std::string> kFs = {"ext4", "ext3", "ext2", "btrfs", "xfs", "f2fs", "zfs", "vfat",
                                                            "exfat", "ntfs", "ntfs3", "fuseblk", "jfs", "reiserfs"};
        std::unordered_set<std::string> seen;
        if (FILE *f = setmntent("/proc/self/mounts", "r")) {
            while (mntent *m = getmntent(f)) {
                std::string dir = m->mnt_dir;
                if (!kFs.count(m->mnt_type) || dir.rfind("/snap/", 0) == 0 || dir.rfind("/boot", 0) == 0) continue;
                if (!seen.insert(m->mnt_fsname).second) continue;
                struct statvfs vs;
                if (statvfs(dir.c_str(), &vs) != 0 || vs.f_blocks == 0) continue;
                w.beginObj().kv("path", dir).kv("fs", m->mnt_type).kv("device", m->mnt_fsname)
                    .kv("total", (uint64_t)vs.f_blocks * vs.f_frsize).kv("free", (uint64_t)vs.f_bavail * vs.f_frsize).endObj();
            }
            endmntent(f);
        }
        w.endArr().endObj();
        return jsonResponse(w);
    }

    Response progress() {
        std::shared_ptr<ScanProgress> prog;
        {
            std::lock_guard<std::mutex> pl(progMu_);
            prog = progress_;
        }
        bool ready;
        {
            std::shared_lock<std::shared_mutex> lk(treeMu_);
            ready = tree_ != nullptr;
        }
        JsonWriter w;
        w.beginObj().kv("ready", ready).kv("running", prog && prog->running.load());
        if (prog) {
            std::lock_guard<std::mutex> l(prog->mu);
            w.kv("files", prog->files.load()).kv("dirs", prog->dirs.load()).kv("bytes", prog->bytes.load())
                .kv("errors", prog->errors.load()).kv("seconds", prog->seconds()).kv("current", display(prog->current))
                .kv("error", prog->error);
        }
        w.endObj();
        return jsonResponse(w);
    }

    Response summary(const Tree &t) {
        const Node &r = t.nodes[t.root];
        struct statvfs vs {};
        statvfs(t.rootPath.c_str(), &vs);
        JsonWriter w;
        w.beginObj().kv("root", t.rootPath).kv("display", display(t.rootPath)).kv("rootId", t.root).kv("size", r.size)
            .kv("bytes", r.bytes).kv("files", t.files).kv("dirs", t.dirs).kv("errors", t.errors).kv("seconds", t.seconds)
            .kv("threads", t.threads).kv("diskTotal", (uint64_t)vs.f_blocks * vs.f_frsize)
            .kv("diskFree", (uint64_t)vs.f_bavail * vs.f_frsize).key("top").beginArr();
        auto kids = sortedChildren(t, t.root);
        for (size_t i = 0; i < kids.size() && i < 12; i++) {
            w.beginObj();
            nodeFields(w, t, kids[i]);
            w.endObj();
        }
        w.endArr().endObj();
        return jsonResponse(w);
    }

    Response node(const Tree &t, const Request &rq) {
        uint32_t id = (uint32_t)toU64(rq.param("id"), t.root);
        if (!t.valid(id)) id = t.root;
        if (t.nodes[id].type != T_DIR) id = t.nodes[id].parent;
        size_t limit = std::clamp<uint64_t>(toU64(rq.param("limit"), 500), 1, 5000);
        auto kids = sortedChildren(t, id);
        JsonWriter w;
        w.beginObj().key("node").beginObj();
        nodeFields(w, t, id);
        w.kv("path", display(t.path(id))).endObj().key("crumbs").beginArr();
        std::vector<uint32_t> chain;
        for (uint32_t c = id; c != kNone; c = t.nodes[c].parent) chain.push_back(c);
        for (size_t i = chain.size(); i-- > 0;)
            w.beginObj().kv("id", chain[i]).kv("name", chain[i] == t.root ? display(t.rootPath) : std::string(t.nodes[chain[i]].name)).endObj();
        w.endArr().key("children").beginArr();
        size_t n = std::min(kids.size(), limit);
        uint64_t rest = 0;
        for (size_t i = 0; i < kids.size(); i++) {
            if (i >= n) { rest += t.nodes[kids[i]].size; continue; }
            w.beginObj();
            nodeFields(w, t, kids[i]);
            w.endObj();
        }
        w.endArr().kv("restCount", (uint64_t)(kids.size() - n)).kv("restSize", rest).endObj();
        return jsonResponse(w);
    }

    Response tree(const Tree &t, const Request &rq) {
        uint32_t id = (uint32_t)toU64(rq.param("id"), t.root);
        if (!t.valid(id) || t.nodes[id].type != T_DIR) id = t.root;
        JsonWriter w;
        writeTree(w, t, id, 2, std::clamp<uint64_t>(toU64(rq.param("limit"), 40), 1, 200), 14);
        return jsonResponse(w);
    }

    Response topFiles(const Tree &t, const Request &rq, bool old) {
        size_t limit = std::clamp<uint64_t>(toU64(rq.param("limit"), 300), 1, 3000);
        int64_t cutoff = old ? time(nullptr) - (int64_t)toU64(rq.param("days"), 365) * 86400 : INT64_MAX;
        uint64_t minSize = old ? toU64(rq.param("min"), 10'000'000) : 1;
        using P = std::pair<uint64_t, uint32_t>;
        std::priority_queue<P, std::vector<P>, std::greater<P>> heap;
        uint64_t count = 0, total = 0;
        for (uint32_t i = 0, n = t.nodes.size(); i < n; i++) {
            const Node &x = t.nodes[i];
            if (!x.name || x.type != T_FILE || (x.flags & F_DELETED) || x.size < minSize || x.mtime > cutoff) continue;
            count++;
            total += x.size;
            if (heap.size() < limit) heap.push({x.size, i});
            else if (x.size > heap.top().first) { heap.pop(); heap.push({x.size, i}); }
        }
        std::vector<uint32_t> ids;
        for (; !heap.empty(); heap.pop()) ids.push_back(heap.top().second);
        std::reverse(ids.begin(), ids.end());
        JsonWriter w;
        w.beginObj().kv("count", count).kv("total", total).key("items").beginArr();
        for (uint32_t id : ids) {
            w.beginObj();
            nodeFields(w, t, id);
            w.kv("dir", display(t.path(t.nodes[id].parent))).kv("parent", t.nodes[id].parent).endObj();
        }
        w.endArr().endObj();
        return jsonResponse(w);
    }

    Response types(const Tree &t) {
        std::unordered_map<std::string, std::pair<uint64_t, uint64_t>> m;
        for (uint32_t i = 0, n = t.nodes.size(); i < n; i++) {
            const Node &x = t.nodes[i];
            if (!x.name || x.type != T_FILE || (x.flags & F_DELETED)) continue;
            auto &e = m[extOf(x.name)];
            e.first += x.size;
            e.second++;
        }
        std::vector<std::pair<std::string, std::pair<uint64_t, uint64_t>>> v(m.begin(), m.end());
        std::sort(v.begin(), v.end(), [](auto &a, auto &b) { return a.second.first > b.second.first; });
        JsonWriter w;
        w.beginObj().key("types").beginArr();
        for (size_t i = 0; i < v.size() && i < 80; i++)
            w.beginObj().kv("ext", v[i].first).kv("size", v[i].second.first).kv("count", v[i].second.second).endObj();
        w.endArr().endObj();
        return jsonResponse(w);
    }

    Response smart(const Tree &t) {
        auto cats = analyzeSmart(t, home_);
        uint64_t safe = 0;
        for (auto &c : cats)
            if (c.safety == "safe") safe += c.total;
        JsonWriter w;
        w.beginObj().kv("safeTotal", safe).key("categories").beginArr();
        for (auto &c : cats) {
            w.beginObj().kv("id", c.id).kv("title", c.title).kv("safety", c.safety).kv("description", c.description)
                .kv("hint", c.hint).kv("total", c.total).kv("count", (uint64_t)c.items.size()).key("items").beginArr();
            for (size_t i = 0; i < c.items.size() && i < 300; i++) {
                w.beginObj();
                nodeFields(w, t, c.items[i]);
                w.kv("path", display(t.path(c.items[i]))).endObj();
            }
            w.endArr().endObj();
        }
        w.endArr().endObj();
        return jsonResponse(w);
    }

    Response open(const Tree &t, const Json &body) {
        uint32_t id = (uint32_t)body["id"].num(-1);
        if (!t.valid(id)) return errorResponse(404, "no such entry");
        if (t.nodes[id].type != T_DIR) id = t.nodes[id].parent;
        spawnQuiet({"xdg-open", t.path(id)});
        return errorResponse(200, "opened");
    }

    Response dupesStart(const Json &body) {
        uint64_t minSize = std::max<uint64_t>(4096, (uint64_t)body["minSize"].num(1 << 20));
        std::lock_guard<std::mutex> jl(jobMu_);
        if (scanning_) return errorResponse(409, "wait for the scan to finish");
        stopDupesLocked();
        std::vector<DupeCandidate> cands;
        {
            std::shared_lock<std::shared_mutex> lk(treeMu_);
            if (!tree_) return errorResponse(409, "no scan yet");
            const Tree &t = *tree_;
            for (uint32_t i = 0, n = t.nodes.size(); i < n; i++) {
                const Node &x = t.nodes[i];
                if (x.name && x.type == T_FILE && !(x.flags & (F_DELETED | F_HARDLINK)) && x.bytes >= minSize)
                    cands.push_back({i, x.bytes, t.path(i)});
            }
        }
        auto job = std::make_shared<DupeJob>();
        job->state = 1;
        dupes_ = job;
        dupeThread_ = std::thread([job, c = std::move(cands)]() mutable { findDuplicates(std::move(c), *job, 4); });
        JsonWriter w;
        w.beginObj().kv("state", 1).endObj();
        return jsonResponse(w);
    }

    Response dupesStatus() {
        auto job = dupes();
        JsonWriter w;
        w.beginObj().kv("state", job ? job->state.load() : 0);
        if (job) {
            std::lock_guard<std::mutex> l(job->mu);
            w.kv("stage", job->stage).kv("filesTotal", job->filesTotal.load()).kv("filesDone", job->filesDone.load())
                .kv("bytesTotal", job->bytesTotal.load()).kv("bytesDone", job->bytesDone.load());
            if (job->state == 2) {
                std::shared_lock<std::shared_mutex> lk(treeMu_);
                uint64_t wasted = 0, shown = 0, groups = 0;
                w.key("groups").beginArr();
                for (auto &g : job->groups) {
                    std::vector<uint32_t> live;
                    for (uint32_t id : g.ids)
                        if (tree_ && tree_->valid(id)) live.push_back(id);
                    if (live.size() < 2) continue;
                    groups++;
                    wasted += g.bytes * (live.size() - 1);
                    if (shown++ >= 300) continue;
                    w.beginObj().kv("bytes", g.bytes).kv("wasted", g.bytes * (live.size() - 1)).key("files").beginArr();
                    for (uint32_t id : live) {
                        w.beginObj();
                        nodeFields(w, *tree_, id);
                        w.kv("dir", display(tree_->path(tree_->nodes[id].parent))).endObj();
                    }
                    w.endArr().endObj();
                }
                w.endArr().kv("groupCount", groups).kv("wastedTotal", wasted);
            }
        }
        w.endObj();
        return jsonResponse(w);
    }

    Response clean(const Json &body) {
        std::lock_guard<std::mutex> cl(cleanMu_);
        if (scanning_) return errorResponse(409, "wait for the scan to finish");
        bool toTrash = body["mode"].str("trash") != "delete";
        uint64_t freed = 0, trashed = 0;
        std::string rootPath;
        JsonWriter w;
        w.beginObj().key("results").beginArr();
        for (const Json &v : body["ids"].a) {
            uint32_t id = (uint32_t)v.num(-1);
            std::string path, reason;
            Node rec;
            {
                std::shared_lock<std::shared_mutex> lk(treeMu_);
                if (!tree_ || !tree_->valid(id)) {
                    w.beginObj().kv("id", id).kv("ok", true).kv("error", "already removed").endObj();
                    continue;
                }
                path = tree_->path(id);
                rec = tree_->nodes[id];
                rootPath = tree_->rootPath;
                reason = protectedReason(path, home_, rootPath);
            }
            CleanResult r;
            if (reason.empty()) r = cleanEntry(path, rec, toTrash, home_);
            else r.error = reason;
            if (r.ok || r.gone) {
                std::unique_lock<std::shared_mutex> lk(treeMu_);
                if (tree_ && tree_->valid(id)) detachNode(*tree_, id);
            }
            freed += r.freed;
            trashed += r.trashed;
            w.beginObj().kv("id", id).kv("ok", r.ok || r.gone).kv("path", display(path)).kv("freed", r.freed)
                .kv("trashed", r.trashed).kv("error", r.error).endObj();
        }
        struct statvfs vs {};
        statvfs(rootPath.empty() ? "/" : rootPath.c_str(), &vs);
        w.endArr().kv("freed", freed).kv("trashed", trashed).kv("diskFree", (uint64_t)vs.f_bavail * vs.f_frsize).endObj();
        return jsonResponse(w);
    }

    std::string home_, token_;
    std::shared_mutex treeMu_;  // guards tree_ and its contents
    std::unique_ptr<Tree> tree_;
    std::mutex progMu_, jobMu_, cleanMu_;  // lock order: cleanMu_ -> jobMu_ -> treeMu_
    std::shared_ptr<ScanProgress> progress_;
    std::atomic<bool> scanning_{false};
    std::thread scanThread_, dupeThread_;
    std::shared_ptr<DupeJob> dupes_;
};

int runCli(const std::string &path, unsigned threads, bool showSmart, uint64_t dupesMin, const std::string &home) {
    ScanProgress prog;
    std::atomic<bool> done{false};
    std::thread ticker([&] {
        while (!done) {
            fprintf(stderr, "\r  scanning... %10lu files %9lu folders %10s", prog.files.load(), prog.dirs.load(), human(prog.bytes).c_str());
            usleep(150000);
        }
    });
    auto t = scanTree({path, threads, false}, prog);
    done = true;
    ticker.join();
    fprintf(stderr, "\r\033[K");
    if (!t) {
        fprintf(stderr, "error: %s\n", prog.error.c_str());
        return 1;
    }
    const Node &r = t->nodes[t->root];
    printf("%s\n  %s on disk (%s apparent), %lu files, %lu folders, %lu unreadable\n  scanned in %.2f s with %u threads: %.0f entries/s\n\n",
           t->rootPath.c_str(), human(r.size).c_str(), human(r.bytes).c_str(), t->files, t->dirs, t->errors, t->seconds,
           t->threads, (t->files + t->dirs) / std::max(t->seconds, 1e-6));
    auto kids = sortedChildren(*t, t->root);
    for (size_t i = 0; i < kids.size() && i < 15; i++) {
        const Node &k = t->nodes[kids[i]];
        int bar = r.size ? (int)(30.0 * k.size / r.size + 0.5) : 0;
        printf("  %10s  %-30s %s%s\n", human(k.size).c_str(), std::string(bar, '#').c_str(), k.name, k.type == T_DIR ? "/" : "");
    }
    if (showSmart) {
        printf("\nCleanup suggestions:\n");
        for (auto &c : analyzeSmart(*t, home)) {
            printf("  [%-6s] %10s  %s (%zu items)\n", c.safety.c_str(), human(c.total).c_str(), c.title.c_str(), c.items.size());
            for (size_t i = 0; i < c.items.size() && i < 3; i++)
                printf("             %10s  %s\n", human(t->nodes[c.items[i]].size).c_str(), t->path(c.items[i]).c_str());
        }
    }
    if (dupesMin) {
        std::vector<DupeCandidate> cands;
        for (uint32_t i = 0, n = t->nodes.size(); i < n; i++) {
            const Node &x = t->nodes[i];
            if (x.name && x.type == T_FILE && !(x.flags & F_HARDLINK) && x.bytes >= dupesMin) cands.push_back({i, x.bytes, t->path(i)});
        }
        DupeJob job;
        auto t0 = std::chrono::steady_clock::now();
        findDuplicates(std::move(cands), job, 4);
        double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        uint64_t wasted = 0;
        for (auto &g : job.groups) wasted += g.bytes * (g.ids.size() - 1);
        printf("\nDuplicates (files >= %s): %zu groups, %s wasted, %s hashed in %.1f s\n", human(dupesMin).c_str(),
               job.groups.size(), human(wasted).c_str(), human(job.bytesDone).c_str(), secs);
        for (size_t i = 0; i < job.groups.size() && i < 8; i++) {
            auto &g = job.groups[i];
            printf("  %zu x %s\n", g.ids.size(), human(g.bytes).c_str());
            for (uint32_t id : g.ids) printf("      %s\n", t->path(id).c_str());
        }
    }
    return 0;
}

void usage(const char *argv0) {
    printf("diskscan %s - ultra fast disk usage scanner and cleanup tool\n\n"
           "  %s [PATH]                 open the GUI (and start scanning PATH)\n"
           "  %s --cli PATH [--smart] [--dupes MB]\n"
           "                            scan in the terminal; --smart lists cleanup suggestions,\n"
           "                            --dupes finds duplicate files of at least MB megabytes\n\n"
           "Options: --threads N  --port N  --no-browser  --stay (don't quit when the window closes)\n",
           kVersion, argv0, argv0);
}

} // namespace

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    std::string path;
    bool cli = false, showSmart = false, noBrowser = false, stay = false;
    unsigned threads = 0;
    uint16_t port = 0;
    uint64_t dupesMb = 0;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() { return i + 1 < argc ? std::string(argv[++i]) : std::string(); };
        if (a == "--cli") cli = true;
        else if (a == "--smart") showSmart = true;
        else if (a == "--dupes") dupesMb = toU64(next(), 1);
        else if (a == "--threads") threads = (unsigned)toU64(next(), 0);
        else if (a == "--port") port = (uint16_t)toU64(next(), 0);
        else if (a == "--no-browser") noBrowser = true;
        else if (a == "--stay") stay = true;
        else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else if (!a.empty() && a[0] == '-') { fprintf(stderr, "unknown option %s\n", a.c_str()); return 2; }
        else path = a;
    }
    std::string home = homeDir();
    if (cli) return runCli(path.empty() ? home : path, threads, showSmart, dupesMb * 1'000'000, home);

    App app(home, randomToken());
    HttpServer server;
    if (!server.listen(port)) {
        perror("listen");
        return 1;
    }
    app.port = server.port();
    std::string url = "http://127.0.0.1:" + std::to_string(app.port) + "/#" + app.token();
    printf("diskscan %s is running at\n  %s\nCtrl+C quits.\n", kVersion, url.c_str());
    fflush(stdout);
    if (!path.empty()) app.startScan(path, threads, false);
    if (!noBrowser) openWindow(url);

    // Quit a few seconds after the window closes (a reload pings again and cancels it),
    // or after 3 minutes without any request from the UI.
    if (!stay)
        std::thread([&app] {
            for (;;) {
                sleep(1);
                int64_t now = nowMs(), bye = app.byeAt, ping = app.lastPing;
                bool closed = bye && ping <= bye && now - bye > 4000;
                bool silent = ping && now - ping > 180000;
                if ((closed || silent) && !app.busy()) {
                    printf("Window closed, exiting.\n");
                    _exit(0);
                }
            }
        }).detach();
    server.run([&app](const Request &rq) { return app.handle(rq); });
}
