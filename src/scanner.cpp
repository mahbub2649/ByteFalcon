// scanner.cpp: parallel directory traversal.
//
// Why it's fast:
//  - N worker threads share a LIFO stack of directories (depth-first keeps memory bounded
//    and directory metadata hot in cache); each worker pushes all subdirectories of a
//    directory in one locked batch.
//  - getdents64() with a 256 KiB buffer reads thousands of entries per syscall
//    (readdir() reads ~32 KiB at a time).
//  - statx() relative to the open directory fd: one path component to resolve instead
//    of the whole path, and only the fields we need.
//  - Many threads keep the SSD's queue full on a cold cache; on a warm cache they use all cores.
//  - Counters are accumulated per directory, not per file, to avoid atomic contention.
#include "scanner.hpp"
#include <cerrno>
#include <climits>
#include <condition_variable>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <thread>
#include <unistd.h>
#include <unordered_set>

namespace ds {
namespace {

constexpr unsigned kStatxMask = STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_INO | STATX_SIZE | STATX_BLOCKS | STATX_MTIME;
constexpr uint32_t kBlock = 2048;         // node indices a worker reserves at a time
constexpr size_t kDentsBuf = 256 * 1024;  // getdents64 buffer

struct InodeKey {
    uint64_t dev, ino;
    bool operator==(const InodeKey &o) const { return dev == o.dev && ino == o.ino; }
};
struct InodeHash {
    size_t operator()(const InodeKey &k) const { return (k.ino * 0x9E3779B97F4A7C15ULL) ^ k.dev; }
};

// Files with several hard links are counted once. Sharded so threads rarely share a lock.
class InodeSet {
public:
    bool insert(uint64_t dev, uint64_t ino) {
        InodeKey k{dev, ino};
        Shard &s = shards_[InodeHash()(k) % kShards];
        std::lock_guard<std::mutex> lk(s.mu);
        return s.set.insert(k).second;
    }

private:
    static constexpr int kShards = 64;
    struct Shard {
        std::mutex mu;
        std::unordered_set<InodeKey, InodeHash> set;
    } shards_[kShards];
};

class WorkQueue {
public:
    void push(std::vector<uint32_t> &items) {
        if (items.empty()) return;
        {
            std::lock_guard<std::mutex> lk(mu_);
            stack_.insert(stack_.end(), items.begin(), items.end());
        }
        if (items.size() == 1) cv_.notify_one();
        else cv_.notify_all();
        items.clear();
    }
    // Next directory to scan; false once the stack is empty and every worker is idle.
    bool next(uint32_t &out, bool finishedOne) {
        std::unique_lock<std::mutex> lk(mu_);
        if (finishedOne) active_--;
        while (stack_.empty()) {
            if (active_ == 0) {
                done_ = true;
                cv_.notify_all();
                return false;
            }
            cv_.wait(lk);
            if (done_) return false;
        }
        out = stack_.back();
        stack_.pop_back();
        active_++;
        return true;
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::vector<uint32_t> stack_;
    int active_ = 0;
    bool done_ = false;
};

struct Worker {
    StringArena *arena = nullptr;
    uint32_t next = 0, end = 0;  // reserved node indices
    std::vector<uint32_t> subdirs;
    std::unique_ptr<char[]> buf{new char[kDentsBuf]};
    unsigned counter = 0;
};

class Scanner {
public:
    Scanner(Tree &t, const ScanOptions &o, ScanProgress &p, uint64_t rootDev)
        : tree_(t), opt_(o), prog_(p), rootDev_(rootDev) {}

    void run(Worker &w) {
        uint32_t id;
        bool did = false;
        while (queue_.next(id, did)) {
            if (!prog_.cancel.load(std::memory_order_relaxed)) scanDir(id, w);
            did = true;
        }
    }
    WorkQueue &queue() { return queue_; }

private:
    uint32_t alloc(Worker &w) {
        if (w.next == w.end) {
            w.next = tree_.nodes.reserve(kBlock);
            w.end = w.next + kBlock;
        }
        return w.next++;
    }

    void scanDir(uint32_t dirId, Worker &w) {
        std::string path = tree_.path(dirId);
        Node &dir = tree_.nodes[dirId];
        int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | (dirId == tree_.root ? 0 : O_NOFOLLOW));
        if (fd < 0) {
            dir.flags |= F_ERROR;
            prog_.errors++;
            prog_.dirs++;
            return;
        }
        if (++w.counter % 64 == 0) {
            std::unique_lock<std::mutex> lk(prog_.mu, std::try_to_lock);
            if (lk) prog_.current = path;
        }
        uint64_t files = 0, bytes = 0, errors = 0;
        for (;;) {
            ssize_t n = getdents64(fd, w.buf.get(), kDentsBuf);
            if (n <= 0) {
                if (n < 0) { dir.flags |= F_ERROR; errors++; }
                break;
            }
            for (ssize_t off = 0; off < n;) {
                auto *e = reinterpret_cast<struct dirent64 *>(w.buf.get() + off);
                off += e->d_reclen;
                const char *name = e->d_name;
                if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) continue;

                struct statx sx;
                if (statx(fd, name, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_STATX_DONT_SYNC, kStatxMask, &sx) != 0) {
                    errors++;
                    continue;
                }
                uint32_t id = alloc(w);
                Node &nd = tree_.nodes[id];
                nd.name = w.arena->add(name, strlen(name));
                nd.parent = dirId;
                nd.nextSibling = dir.firstChild;  // only this worker touches dir's child list
                dir.firstChild = id;
                nd.mtime = sx.stx_mtime.tv_sec;
                nd.bytes = sx.stx_size;
                nd.size = sx.stx_blocks * 512;

                if (S_ISDIR(sx.stx_mode)) {
                    nd.type = T_DIR;
                    if (!opt_.crossFs && makedev(sx.stx_dev_major, sx.stx_dev_minor) != rootDev_) nd.flags |= F_MOUNT;
                    else w.subdirs.push_back(id);
                } else if (S_ISREG(sx.stx_mode)) {
                    nd.type = T_FILE;
                    if (sx.stx_nlink > 1 && !inodes_.insert(makedev(sx.stx_dev_major, sx.stx_dev_minor), sx.stx_ino)) {
                        nd.flags |= F_HARDLINK;
                        nd.size = 0;  // already counted through another link
                    }
                    files++;
                    bytes += nd.size;
                    if (strcmp(name, "CACHEDIR.TAG") == 0) dir.flags |= F_CACHEDIR;
                } else if (S_ISLNK(sx.stx_mode)) {
                    nd.type = T_LINK;
                } else {
                    nd.type = T_OTHER;
                }
            }
        }
        close(fd);
        prog_.files += files;
        prog_.bytes += bytes;
        prog_.errors += errors;
        prog_.dirs++;
        queue_.push(w.subdirs);
    }

    Tree &tree_;
    const ScanOptions &opt_;
    ScanProgress &prog_;
    uint64_t rootDev_;
    WorkQueue queue_;
    InodeSet inodes_;
};

// Bottom-up totals. Node indices aren't in topological order (threads reserve blocks),
// so walk the directories explicitly and fold them in reverse pre-order.
void finalizeTree(Tree &t) {
    std::vector<uint32_t> order, stack{t.root};
    while (!stack.empty()) {
        uint32_t id = stack.back();
        stack.pop_back();
        order.push_back(id);
        for (uint32_t c = t.nodes[id].firstChild; c != kNone; c = t.nodes[c].nextSibling)
            if (t.nodes[c].type == T_DIR) stack.push_back(c);
    }
    for (size_t i = order.size(); i-- > 0;) {
        Node &d = t.nodes[order[i]];
        uint64_t s = d.size, b = d.bytes;
        uint32_t f = 0;
        for (uint32_t c = d.firstChild; c != kNone; c = t.nodes[c].nextSibling) {
            const Node &k = t.nodes[c];
            s += k.size;
            b += k.bytes;
            f += k.type == T_DIR ? k.files : (k.type == T_FILE ? 1 : 0);
        }
        d.size = s;
        d.bytes = b;
        d.files = f;
    }
    t.dirs = order.size();
    t.files = t.nodes[t.root].files;
}

} // namespace

unsigned defaultScanThreads() {
    unsigned hw = std::max(1u, std::thread::hardware_concurrency());
    return std::clamp(hw * 2, 4u, 32u);
}

std::unique_ptr<Tree> scanTree(const ScanOptions &opt, ScanProgress &prog) {
    auto fail = [&](const std::string &msg) {
        std::lock_guard<std::mutex> lk(prog.mu);
        prog.error = msg;
        return std::unique_ptr<Tree>();
    };
    char real[PATH_MAX];
    if (!realpath(opt.root.c_str(), real)) return fail(opt.root + ": " + strerror(errno));
    struct statx sx;
    if (statx(AT_FDCWD, real, 0, kStatxMask, &sx) != 0) return fail(std::string(real) + ": " + strerror(errno));
    if (!S_ISDIR(sx.stx_mode)) return fail(std::string(real) + " is not a folder");

    auto tree = std::make_unique<Tree>();
    tree->rootPath = real;
    tree->arenas.push_back(std::make_unique<StringArena>());
    tree->root = tree->nodes.reserve(1);
    Node &r = tree->nodes[tree->root];
    r.name = tree->arenas[0]->add(real, strlen(real));
    r.type = T_DIR;
    r.size = sx.stx_blocks * 512;
    r.bytes = sx.stx_size;
    r.mtime = sx.stx_mtime.tv_sec;

    unsigned n = opt.threads ? std::clamp(opt.threads, 1u, 128u) : defaultScanThreads();
    Scanner sc(*tree, opt, prog, makedev(sx.stx_dev_major, sx.stx_dev_minor));
    std::vector<uint32_t> first{tree->root};
    sc.queue().push(first);

    std::vector<std::unique_ptr<Worker>> workers;
    for (unsigned i = 0; i < n; i++) {
        tree->arenas.push_back(std::make_unique<StringArena>());
        workers.push_back(std::make_unique<Worker>());
        workers.back()->arena = tree->arenas.back().get();
    }
    std::vector<std::thread> threads;
    for (auto &w : workers) threads.emplace_back([&sc, wp = w.get()] { sc.run(*wp); });
    for (auto &t : threads) t.join();
    if (prog.cancel) return fail("scan cancelled");

    finalizeTree(*tree);
    tree->threads = n;
    tree->seconds = prog.seconds();
    tree->errors = prog.errors;
    return tree;
}

} // namespace ds
