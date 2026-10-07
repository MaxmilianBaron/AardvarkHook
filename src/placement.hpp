#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace aardvark::hook::detail {

struct AddressRange {
    std::uintptr_t lower = 0, upper = 0;

    bool constrain(std::uintptr_t endpoint, std::size_t offset, std::uintptr_t before,
                   std::uintptr_t after) noexcept {
        std::uintptr_t first = 0, last = 0;
        if (endpoint >= offset) {
            const auto center = endpoint - offset;
            first = center > before ? center - before : 0;
            const auto maximum = std::numeric_limits<std::uintptr_t>::max();
            last = after > maximum - center ? maximum : center + after;
        } else {
            const auto distance = offset - endpoint;
            if (after < distance)
                return false;
            last = after - distance;
        }
        lower = std::max(lower, first);
        upper = std::min(upper, last);
        return lower <= upper;
    }
};

struct MemoryRegion {
    std::uintptr_t base = 0, allocation = 0;
    std::size_t size = 0;
    bool available = false;
};

template <class Query, class Reserve>
std::uintptr_t place_near(AddressRange range, std::uintptr_t target, std::size_t size,
                          std::uintptr_t granularity, Query query, Reserve reserve) noexcept {
    const auto maximum = std::numeric_limits<std::uintptr_t>::max();
    if (!size || !granularity || (granularity & (granularity - 1)) || range.lower > range.upper ||
        range.lower > maximum - (granularity - 1))
        return 0;
    const auto lower = (range.lower + granularity - 1) & ~(granularity - 1);
    const auto upper = range.upper & ~(granularity - 1);
    if (lower > upper)
        return 0;
    const auto pivot = target & ~(granularity - 1);
    auto down = std::min(pivot, upper);
    auto up = pivot > maximum - granularity ? maximum : std::max(lower, pivot + granularity);
    bool descending = down >= lower, ascending = up <= upper && up > pivot;
    while (descending || ascending) {
        const bool below = descending && (!ascending || target - down <= up - target);
        const auto candidate = below ? down : up;
        MemoryRegion region{};
        const bool valid =
            query(candidate, region) && region.base <= candidate && candidate - region.base < region.size;
        if (valid && candidate && size - 1 <= maximum - candidate && region.available &&
            size <= region.size - (candidate - region.base) && reserve(candidate, size))
            return candidate;
        if (below) {
            auto boundary = candidate;
            if (valid && !region.available)
                boundary =
                    region.allocation && region.allocation <= candidate ? region.allocation : region.base;
            if (!boundary) {
                descending = false;
            } else {
                down = (boundary - 1) & ~(granularity - 1);
                descending = down >= lower && down < candidate;
            }
        } else {
            auto boundary = candidate > maximum - granularity ? maximum : candidate + granularity;
            if (valid && !region.available) {
                const auto end = region.size > maximum - region.base ? maximum : region.base + region.size;
                boundary = std::max(boundary, end);
            }
            if (boundary > maximum - (granularity - 1)) {
                ascending = false;
            } else {
                up = (boundary + granularity - 1) & ~(granularity - 1);
                ascending = up <= upper && up > candidate;
            }
        }
    }
    return 0;
}

}
