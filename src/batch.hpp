#pragma once

#include <aardvark/hook.hpp>

namespace aardvark::hook::detail {

template <class Validate, class Read, class Write>
BatchResult commit_changes(std::size_t count, Validate validate, Read read, Write write) noexcept {
    std::array<bool, 64> before{};
    if (count > before.size())
        return {Status::capacity_exceeded};
    for (std::size_t i = 0; i < count; ++i) {
        const auto status = validate(i);
        if (status != Status::ok)
            return {status, i};
        before[i] = read(i);
    }
    for (std::size_t i = 0; i < count; ++i) {
        const auto status = write(i, false, false);
        if (status == Status::ok)
            continue;
        BatchResult result{status, i};
        for (std::size_t undo = i + 1; undo > 0;) {
            --undo;
            const auto restored = write(undo, true, before[undo]);
            if (restored != Status::ok && result.rollback_status == Status::ok) {
                result.rollback_status = restored;
                result.rollback_index = undo;
            }
        }
        return result;
    }
    return {};
}

}
