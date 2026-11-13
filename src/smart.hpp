// smart.hpp: rule-based cleanup suggestions.
#pragma once
#include "tree.hpp"

namespace ds {

struct SmartCategory {
    std::string id, title, safety, description, hint;  // safety: "safe" | "review" | "info"
    std::vector<uint32_t> items;                       // biggest first
    uint64_t total = 0;
};

std::vector<SmartCategory> analyzeSmart(const Tree &t, const std::string &home);

} // namespace ds
