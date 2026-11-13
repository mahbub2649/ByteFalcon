// tree.hpp: compact in-memory file tree shared by the scanner, the analysers and the API.
#pragma once
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace ds {

constexpr uint32_t kNone = 0xFFFFFFFFu;

enum : uint8_t { T_FILE, T_DIR, T_LINK, T_OTHER };
enum : uint8_t { F_DELETED = 1, F_HARDLINK = 2, F_CACHEDIR = 4, F_ERROR = 8, F_MOUNT = 16 };

// 56 bytes per entry. Children are a singly linked list (firstChild/nextSibling),
// so a directory needs no vector of its own.
struct Node {
    const char *name = nullptr;  // NUL-terminated, owned by a StringArena; nullptr = unused slot
    uint64_t size = 0;           // allocated bytes on disk (dirs: whole subtree after finalize)
    uint64_t bytes = 0;          // apparent size (dirs: whole subtree)
    int64_t mtime = 0;
    uint32_t parent = kNone, firstChild = kNone, nextSibling = kNone;
    uint32_t files = 0;          // dirs: regular files in the subtree
    uint8_t type = T_OTHER, flags = 0;
};

// Chunked storage that never moves, so worker threads can append while others read.
// Each thread reserves blocks of indices, so allocation is one atomic add per block.
class NodeStore {
public:
    static constexpr uint32_t kChunkBits = 16, kChunkSize = 1u << kChunkBits, kMaxChunks = 1u << 16;

    NodeStore() : chunks_(new std::atomic<Node *>[kMaxChunks]) {
        for (uint32_t i = 0; i < kMaxChunks; i++) chunks_[i].store(nullptr, std::memory_order_relaxed);
    }
    ~NodeStore() {
        for (uint32_t i = 0; i < kMaxChunks; i++) delete[] chunks_[i].load(std::memory_order_relaxed);
    }
    NodeStore(const NodeStore &) = delete;
    NodeStore &operator=(const NodeStore &) = delete;

    uint32_t reserve(uint32_t n) {
        uint32_t base = next_.fetch_add(n, std::memory_order_relaxed);
        for (uint32_t c = base >> kChunkBits, last = (base + n - 1) >> kChunkBits; c <= last; c++) {
            if (chunks_[c].load(std::memory_order_acquire)) continue;
            std::lock_guard<std::mutex> lk(mu_);
            if (!chunks_[c].load(std::memory_order_relaxed))
                chunks_[c].store(new Node[kChunkSize], std::memory_order_release);
        }
        return base;
    }
    Node &operator[](uint32_t i) { return chunks_[i >> kChunkBits].load(std::memory_order_relaxed)[i & (kChunkSize - 1)]; }
    const Node &operator[](uint32_t i) const {
        return chunks_[i >> kChunkBits].load(std::memory_order_relaxed)[i & (kChunkSize - 1)];
    }
    uint32_t size() const { return next_.load(std::memory_order_relaxed); }

private:
    std::unique_ptr<std::atomic<Node *>[]> chunks_;
    std::atomic<uint32_t> next_{0};
    std::mutex mu_;
};

// Bump allocator for names: one malloc per MiB instead of one per file.
class StringArena {
public:
    const char *add(const char *s, size_t n) {
        if (n + 1 > left_) {
            size_t sz = std::max<size_t>(1 << 20, n + 1);
            blocks_.emplace_back(new char[sz]);
            cur_ = blocks_.back().get();
            left_ = sz;
        }
        memcpy(cur_, s, n);
        cur_[n] = 0;
        const char *r = cur_;
        cur_ += n + 1;
        left_ -= n + 1;
        return r;
    }

private:
    std::vector<std::unique_ptr<char[]>> blocks_;
    char *cur_ = nullptr;
    size_t left_ = 0;
};

struct Tree {
    NodeStore nodes;
    std::vector<std::unique_ptr<StringArena>> arenas;
    std::string rootPath;
    uint32_t root = kNone;
    uint64_t files = 0, dirs = 0, errors = 0;
    double seconds = 0;
    unsigned threads = 0;

    bool valid(uint32_t id) const {
        return id < nodes.size() && nodes[id].name && !(nodes[id].flags & F_DELETED);
    }
    // The root node's name is the absolute scan root, so joining names gives the full path.
    std::string path(uint32_t id) const {
        std::vector<const char *> parts;
        for (uint32_t c = id; c != kNone; c = nodes[c].parent) parts.push_back(nodes[c].name);
        std::string p = parts.back();
        for (size_t i = parts.size() - 1; i-- > 0;) {
            if (p.empty() || p.back() != '/') p += '/';
            p += parts[i];
        }
        return p;
    }
    template <class F> void forEachChild(uint32_t id, F f) const {
        for (uint32_t c = nodes[id].firstChild; c != kNone; c = nodes[c].nextSibling)
            if (!(nodes[c].flags & F_DELETED)) f(c);
    }
};

} // namespace ds
