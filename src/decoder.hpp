#pragma once

#include <cstddef>
#include <cstdint>

namespace aardvark::hook::detail {

enum class Branch { none, call, jump, conditional, counter };
struct Instruction {
    std::size_t size = 0;
    std::size_t relative = 0, relative_size = 0;
    std::size_t displacement = 0;
    Branch branch = Branch::none;
    unsigned condition = 0;
    bool rip_relative = false, terminal = false;
};

bool decode(const std::uint8_t *bytes, std::size_t available, bool x64, Instruction &result) noexcept;

}
