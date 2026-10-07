#include "decoder.hpp"
#include <algorithm>

namespace aardvark::hook::detail {

bool decode(const std::uint8_t *bytes, std::size_t available, bool x64, Instruction &out) noexcept {
    out = {};
    if (!bytes || !available)
        return false;
    available = std::min<std::size_t>(available, 15);
    std::size_t at = 0;
    bool word = false;
    unsigned repeat = 0, rex = 0;
    while (at < available && (bytes[at] == 0x66 || bytes[at] == 0xf2 || bytes[at] == 0xf3)) {
        if (bytes[at] == 0x66) {
            if (word)
                return false;
            word = true;
        } else {
            if (repeat)
                return false;
            repeat = bytes[at];
        }
        ++at;
    }
    if (x64 && at < available && (bytes[at] & 0xf0) == 0x40)
        rex = bytes[at++];
    if (at == available)
        return false;
    const unsigned op = bytes[at++];
    const std::size_t operand = word && !(rex & 8) ? 2 : 4;
    std::size_t immediate = 0;
    bool modrm = false, extended = false;
    unsigned second = 0;
    if (op == 0xe8 || op == 0xe9 || op == 0xeb || (op >= 0x70 && op <= 0x7f) || (op >= 0xe0 && op <= 0xe3)) {
        if (word || repeat || rex)
            return false;
        out.branch = op == 0xe8                   ? Branch::call
                     : (op >= 0xe0 && op <= 0xe3) ? Branch::counter
                     : (op >= 0x70 && op <= 0x7f) ? Branch::conditional
                                                  : Branch::jump;
        out.condition = op & 15;
        out.relative = at;
        out.relative_size = (op == 0xe8 || op == 0xe9) ? 4 : 1;
        immediate = out.relative_size;
        out.terminal = out.branch == Branch::jump;
    } else if (op == 0x0f) {
        if (at == available)
            return false;
        extended = true;
        second = bytes[at++];
        if (second >= 0x80 && second <= 0x8f) {
            if (word || repeat || rex)
                return false;
            out.branch = Branch::conditional;
            out.condition = second & 15;
            out.relative = at;
            out.relative_size = immediate = 4;
        } else if (second == 0x1e) {
            if (repeat != 0xf3 || word || rex || at == available || bytes[at++] != (x64 ? 0xfa : 0xfb))
                return false;
        } else {
            const bool scalar = second == 0xaf || second == 0xb6 || second == 0xb7 || second == 0xbe ||
                                second == 0xbf || second == 0x1f || (second >= 0x40 && second <= 0x4f) ||
                                (second >= 0x90 && second <= 0x9f) || second == 0xa3 || second == 0xab ||
                                second == 0xb3 || second == 0xbb || second == 0xba;
            const bool simd = (second >= 0x10 && second <= 0x17) || (second >= 0x28 && second <= 0x2f) ||
                              (second >= 0x54 && second <= 0x5f) || second == 0x6e || second == 0x6f ||
                              second == 0x7e || second == 0x7f || second == 0xef || second == 0x70 ||
                              second == 0xc2 || second == 0xc6;
            if ((!scalar && !simd) || (scalar && repeat))
                return false;
            immediate = second == 0xba || second == 0x70 || second == 0xc2 || second == 0xc6 ? 1 : 0;
            modrm = true;
        }
    } else {
        if (repeat && !(op == 0x90 && repeat == 0xf3))
            return false;
        if ((!x64 && op >= 0x40 && op <= 0x4f) || (op >= 0x50 && op <= 0x5f) || op == 0x90 || op == 0x98 ||
            op == 0x99 || op == 0x9c || op == 0x9d || op == 0xc9) {
        } else if (op == 0xc3 || op == 0xc2) {
            if (word || rex)
                return false;
            out.terminal = true;
            immediate = op == 0xc2 ? 2 : 0;
        } else if (op >= 0xb8 && op <= 0xbf) {
            immediate = rex & 8 ? 8 : operand;
        } else if ((op >= 0xb0 && op <= 0xb7) || op == 0x6a || op == 0xa8) {
            immediate = 1;
        } else if (op == 0x68 || op == 0xa9) {
            immediate = op == 0x68 && word ? 2 : operand;
        } else if (op >= 0xa0 && op <= 0xa3) {
            immediate = x64 ? 8 : 4;
        } else if (op <= 0x3d && (op & 7) <= 5) {
            modrm = (op & 7) < 4;
            if (!modrm)
                immediate = op & 1 ? operand : 1;
        } else {
            switch (op) {
            case 0x63:
                if (!x64)
                    return false;
                modrm = true;
                break;
            case 0x84:
            case 0x85:
            case 0x86:
            case 0x87:
            case 0x88:
            case 0x89:
            case 0x8a:
            case 0x8b:
            case 0x8d:
            case 0x8f:
            case 0xd0:
            case 0xd1:
            case 0xd2:
            case 0xd3:
            case 0xf6:
            case 0xf7:
            case 0xfe:
            case 0xff:
                modrm = true;
                break;
            case 0x80:
            case 0x83:
            case 0xc0:
            case 0xc1:
            case 0xc6:
            case 0x6b:
                modrm = true;
                immediate = 1;
                break;
            case 0x81:
            case 0xc7:
            case 0x69:
                modrm = true;
                immediate = operand;
                break;
            default:
                return false;
            }
        }
    }
    if (modrm) {
        if (at == available)
            return false;
        const unsigned byte = bytes[at++], mod = byte >> 6, reg = (byte >> 3) & 7, rm = byte & 7;
        if (!extended) {
            if (((op == 0xc6 || op == 0xc7 || op == 0x8f) && reg != 0) || (op == 0xfe && reg > 1) ||
                (op == 0xff && (reg == 3 || reg == 5 || reg == 7)) || (op == 0x8d && mod == 3))
                return false;
            if (op == 0xff && reg == 4)
                out.terminal = true;
            if (op == 0xf6 || op == 0xf7) {
                if (reg == 1)
                    return false;
                if (reg == 0)
                    immediate = op == 0xf6 ? 1 : operand;
            }
        } else if ((second == 0x1f && reg != 0) || (second == 0xba && reg < 4)) {
            return false;
        }
        std::size_t displacement = 0;
        if (mod != 3 && rm == 4) {
            if (at == available)
                return false;
            const unsigned sib = bytes[at++];
            if (mod == 0 && (sib & 7) == 5)
                displacement = 4;
        }
        if (mod == 0 && rm == 5) {
            displacement = 4;
            out.rip_relative = x64;
        } else if (mod == 1)
            displacement = 1;
        else if (mod == 2)
            displacement = 4;
        out.displacement = at;
        if (displacement > available - at)
            return false;
        at += displacement;
    }
    if (immediate > available - at)
        return false;
    out.size = at + immediate;
    return true;
}

}
