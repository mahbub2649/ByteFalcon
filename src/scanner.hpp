// scanner.hpp: parallel filesystem scan into a Tree.
#pragma once
#include "tree.hpp"
#include <chrono>

namespace ds {

struct ScanOptions {
    std::string root;
    unsigned threads = 0;  // 0 = automatic
    bool crossFs = false;  // descend into other mounted filesystems
};

struct ScanProgress {
    std::atomic<uint64_t> files{0}, dirs{0}, bytes{0}, errors{0};
    std::atomic<bool> running{false}, cancel{false};
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    std::mutex mu;  // guards current and error
    std::string current, error;

    double seconds() const {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    }
};

unsigned defaultScanThreads();
// Returns nullptr (with progress.error set) if the root can't be scanned or the scan was cancelled.
std::unique_ptr<Tree> scanTree(const ScanOptions &opt, ScanProgress &prog);

} // namespace ds
