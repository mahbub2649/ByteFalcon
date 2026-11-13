// dupes.cpp: three-stage duplicate detection, each stage only reading what the previous
// one couldn't rule out:
//   1. same size        (free, from the scan)
//   2. same head + tail (16 KiB from each end: rules out most same-size files cheaply)
//   3. same content     (two independent XXH64 hashes = 128 bits over the whole file)
// Files are read with POSIX_FADV_DONTNEED afterwards so hashing doesn't push the rest of
// the system out of RAM.
#include "dupes.hpp"
#include "xxhash64.hpp"
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <memory>
#include <thread>
#include <tuple>
#include <unistd.h>

namespace ds {
namespace {

constexpr size_t kEdge = 16 * 1024;
constexpr size_t kBuf = 1 << 20;

struct Item {
    const DupeCandidate *c;
    uint64_t h1 = 0, h2 = 0;
    bool ok = false;
};

template <class F> void parallelFor(size_t n, unsigned threads, F f) {
    std::atomic<size_t> next{0};
    std::vector<std::thread> th;
    for (unsigned t = 0; t < std::max(1u, threads); t++)
        th.emplace_back([&] {
            for (size_t i; (i = next.fetch_add(1)) < n;) f(i);
        });
    for (auto &t : th) t.join();
}

int openForRead(const std::string &path) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOATIME);
    if (fd < 0 && errno == EPERM) fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);  // O_NOATIME needs ownership
    return fd;
}

bool readFully(int fd, char *buf, size_t len, off_t off) {
    while (len) {
        ssize_t n = pread(fd, buf, len, off);
        if (n <= 0) return false;
        buf += n;
        len -= n;
        off += n;
    }
    return true;
}

// Whole file when full is set or the file is small; otherwise head and tail only.
bool hashFile(Item &it, bool full, DupeJob &job) {
    int fd = openForRead(it.c->path);
    if (fd < 0) return false;
    thread_local std::unique_ptr<char[]> buf(new char[kBuf]);
    XXH64 a(0), b(0x9E3779B97F4A7C15ULL);
    uint64_t size = it.c->bytes;
    bool ok = true;
    if (!full && size > 2 * kEdge) {
        ok = readFully(fd, buf.get(), kEdge, 0) && readFully(fd, buf.get() + kEdge, kEdge, size - kEdge);
        if (ok) { a.update(buf.get(), 2 * kEdge); b.update(buf.get(), 2 * kEdge); }
    } else {
        posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
        uint64_t done = 0;
        while (ok && done < size && !job.cancel.load(std::memory_order_relaxed)) {
            ssize_t n = read(fd, buf.get(), kBuf);
            if (n <= 0) { ok = n == 0 && done == size; break; }
            a.update(buf.get(), n);
            b.update(buf.get(), n);
            done += n;
            if (full) job.bytesDone += n;
        }
        ok = ok && done == size;
    }
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    close(fd);
    it.h1 = a.digest();
    it.h2 = b.digest();
    return ok;
}

// Groups items with equal (size, h1, h2), keeping groups of two or more.
std::vector<std::vector<Item>> regroup(std::vector<Item> &items) {
    auto key = [](const Item &i) { return std::make_tuple(i.c->bytes, i.h1, i.h2); };
    std::sort(items.begin(), items.end(), [&](const Item &x, const Item &y) { return key(x) < key(y); });
    std::vector<std::vector<Item>> out;
    for (size_t i = 0; i < items.size();) {
        size_t j = i;
        while (j < items.size() && key(items[j]) == key(items[i])) j++;
        if (j - i >= 2) out.emplace_back(items.begin() + i, items.begin() + j);
        i = j;
    }
    return out;
}

void setStage(DupeJob &job, const char *s) {
    std::lock_guard<std::mutex> lk(job.mu);
    job.stage = s;
}

} // namespace

void findDuplicates(std::vector<DupeCandidate> cands, DupeJob &job, unsigned threads) {
    setStage(job, "grouping by size");
    std::sort(cands.begin(), cands.end(), [](auto &a, auto &b) { return a.bytes < b.bytes; });
    std::vector<Item> sameSize;
    for (size_t i = 0; i < cands.size();) {
        size_t j = i;
        while (j < cands.size() && cands[j].bytes == cands[i].bytes) j++;
        if (j - i >= 2)
            for (size_t k = i; k < j; k++) sameSize.push_back({&cands[k]});
        i = j;
    }

    setStage(job, "comparing file edges");
    job.filesTotal = sameSize.size();
    parallelFor(sameSize.size(), threads, [&](size_t i) {
        if (!job.cancel) sameSize[i].ok = hashFile(sameSize[i], false, job);
        job.filesDone++;
    });
    std::vector<Item> edgeMatch;
    for (auto &g : regroup(sameSize))
        for (auto &it : g)
            if (it.ok) edgeMatch.push_back(it);

    setStage(job, "hashing full contents");
    std::vector<Item> needFull, done;
    for (auto &it : edgeMatch) (it.c->bytes > 2 * kEdge ? needFull : done).push_back(it);  // small files were read whole already
    job.filesTotal = needFull.size();
    job.filesDone = 0;
    uint64_t total = 0;
    for (auto &it : needFull) total += it.c->bytes;
    job.bytesTotal = total;
    parallelFor(needFull.size(), threads, [&](size_t i) {
        if (!job.cancel) needFull[i].ok = hashFile(needFull[i], true, job);
        job.filesDone++;
    });
    for (auto &it : needFull)
        if (it.ok) done.push_back(it);

    std::vector<DupeGroup> groups;
    for (auto &g : regroup(done)) {
        DupeGroup dg{g[0].c->bytes, {}};
        for (auto &it : g) dg.ids.push_back(it.c->id);
        groups.push_back(std::move(dg));
    }
    std::sort(groups.begin(), groups.end(),
              [](auto &a, auto &b) { return a.bytes * (a.ids.size() - 1) > b.bytes * (b.ids.size() - 1); });
    {
        std::lock_guard<std::mutex> lk(job.mu);
        job.groups = std::move(groups);
        job.stage = job.cancel ? "cancelled" : "done";
    }
    job.state = 2;
}

} // namespace ds
