// cleaner.hpp: safe deletion and moving to the Trash.
#pragma once
#include "tree.hpp"

namespace ds {

struct CleanResult {
    bool ok = false;
    bool gone = false;      // was already missing on disk; the tree entry should be dropped
    uint64_t freed = 0;     // bytes actually released (0 when moved to Trash)
    uint64_t trashed = 0;   // bytes moved to Trash
    std::string error;
};

// Empty if the path may be deleted, otherwise the reason it is protected.
std::string protectedReason(const std::string &path, const std::string &home, const std::string &scanRoot);

// Re-checks that the entry on disk still matches the scan, then deletes or trashes it.
// Never follows symlinks and never crosses into another mounted filesystem.
CleanResult cleanEntry(const std::string &path, const Node &recorded, bool toTrash, const std::string &home);

// Drops a deleted entry from the tree and subtracts its size from every ancestor.
void detachNode(Tree &t, uint32_t id);

} // namespace ds
