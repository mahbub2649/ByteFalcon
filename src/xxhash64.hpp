// xxhash64.hpp: streaming XXH64 (Yann Collet's algorithm), ~10 GB/s per core,
// so hashing is limited by the disk, never the CPU.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ds {

class XXH64 {
public:
    explicit XXH64(uint64_t seed = 0) : seed_(seed) {
        v_[0] = seed + P1 + P2;
        v_[1] = seed + P2;
        v_[2] = seed;
        v_[3] = seed - P1;
    }

    void update(const void *data, size_t len) {
        const uint8_t *p = static_cast<const uint8_t *>(data);
        total_ += len;
        if (memSize_ + len < 32) {
            memcpy(mem_ + memSize_, p, len);
            memSize_ += len;
            return;
        }
        if (memSize_) {
            size_t fill = 32 - memSize_;
            memcpy(mem_ + memSize_, p, fill);
            consume(mem_);
            p += fill;
            len -= fill;
            memSize_ = 0;
        }
        for (; len >= 32; p += 32, len -= 32) consume(p);
        if (len) {
            memcpy(mem_, p, len);
            memSize_ = len;
        }
    }

    uint64_t digest() const {
        uint64_t h;
        if (total_ >= 32) {
            h = rotl(v_[0], 1) + rotl(v_[1], 7) + rotl(v_[2], 12) + rotl(v_[3], 18);
            for (uint64_t v : v_) h = merge(h, v);
        } else {
            h = seed_ + P5;
        }
        h += total_;
        const uint8_t *p = mem_;
        size_t len = memSize_;
        for (; len >= 8; p += 8, len -= 8) h = rotl(h ^ round(0, read64(p)), 27) * P1 + P4;
        if (len >= 4) {
            h = rotl(h ^ (uint64_t)read32(p) * P1, 23) * P2 + P3;
            p += 4;
            len -= 4;
        }
        for (; len; p++, len--) h = rotl(h ^ (*p * P5), 11) * P1;
        h ^= h >> 33;
        h *= P2;
        h ^= h >> 29;
        h *= P3;
        h ^= h >> 32;
        return h;
    }

private:
    static constexpr uint64_t P1 = 11400714785074694791ULL, P2 = 14029467366897019727ULL,
                              P3 = 1609587929392839161ULL, P4 = 9650029242287828579ULL, P5 = 2870177450012600261ULL;
    static uint64_t rotl(uint64_t x, int r) { return (x << r) | (x >> (64 - r)); }
    static uint64_t read64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
    static uint32_t read32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
    static uint64_t round(uint64_t acc, uint64_t in) { return rotl(acc + in * P2, 31) * P1; }
    static uint64_t merge(uint64_t acc, uint64_t v) { return (acc ^ round(0, v)) * P1 + P4; }
    void consume(const uint8_t *p) {
        v_[0] = round(v_[0], read64(p));
        v_[1] = round(v_[1], read64(p + 8));
        v_[2] = round(v_[2], read64(p + 16));
        v_[3] = round(v_[3], read64(p + 24));
    }

    uint64_t seed_, v_[4], total_ = 0;
    uint8_t mem_[32];
    size_t memSize_ = 0;
};

} // namespace ds
