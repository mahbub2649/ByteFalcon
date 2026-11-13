// dupes.hpp: duplicate file finder.
#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace ds {

struct DupeCandidate {
    uint32_t id;
    uint64_t bytes;
    std::string path;
};

struct DupeGroup {
    uint64_t bytes;
    std::vector<uint32_t> ids;
};

struct DupeJob {
    std::atomic<int> state{0};  // 0 idle, 1 running, 2 done
    std::atomic<bool> cancel{false};
    std::atomic<uint64_t> filesTotal{0}, filesDone{0}, bytesTotal{0}, bytesDone{0};
    std::mutex mu;  // guards stage and groups
    std::string stage;
    std::vector<DupeGroup> groups;  // biggest waste first
};

// Candidates are copied out of the tree first, so the job never holds the tree lock.
void findDuplicates(std::vector<DupeCandidate> cands, DupeJob &job, unsigned threads);

} // namespace ds
