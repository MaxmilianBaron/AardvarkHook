#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "batch.hpp"
#include "decoder.hpp"
#include "placement.hpp"
#include <aardvark/hook.hpp>
#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <windows.h>

#if !defined(_M_IX86) && !defined(__i386__) && !defined(_M_X64) && !defined(__x86_64__)
#error AardvarkHook requires x86 instructions.
#endif

namespace aardvark::hook {
namespace {

bool read_memory(const void *address, void *output, std::size_t size) noexcept {
    SIZE_T read = 0;
    return ReadProcessMemory(GetCurrentProcess(), address, output, size, &read) && read == size;
}

bool executable_range(const void *address, std::size_t size, DWORD &protection) noexcept {
    const auto start = reinterpret_cast<std::uintptr_t>(address);
    if (!start || !size || start > std::numeric_limits<std::uintptr_t>::max() - size)
        return false;
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQuery(address, &info, sizeof(info)) || info.State != MEM_COMMIT ||
        (info.Protect & PAGE_GUARD))
        return false;
    const auto base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
    if (start < base || start - base >= info.RegionSize || size > info.RegionSize - (start - base))
        return false;
    const DWORD mode = info.Protect & 0xff;
    if (mode != PAGE_EXECUTE_READ && mode != PAGE_EXECUTE_READWRITE && mode != PAGE_EXECUTE_WRITECOPY)
        return false;
    protection = info.Protect;
    return true;
}

void jump(std::uint8_t *output, const void *from, const void *to) noexcept {
    output[0] = 0xe9;
    const auto displacement = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(to) -
                                                         reinterpret_cast<std::uintptr_t>(from) - 5);
    std::memcpy(output + 1, &displacement, sizeof(displacement));
}

constexpr bool x64 = sizeof(void *) == 8;
constexpr std::size_t allocation_size = 4096;

bool relative32(std::uintptr_t from, std::uintptr_t to, std::int32_t &result) noexcept {
    if constexpr (x64) {
        if (to >= from) {
            if (to - from > 0x7fffffffu)
                return false;
        } else if (from - to > 0x80000000u)
            return false;
    }
    const auto bits = static_cast<std::uint32_t>(to - from);
    std::memcpy(&result, &bits, sizeof(result));
    return true;
}

void absolute_jump(std::uint8_t *output, std::uintptr_t to) noexcept {
    const std::uint8_t opcode[] = {0xff, 0x25, 0, 0, 0, 0};
    const std::uint64_t address = to;
    std::memcpy(output, opcode, sizeof(opcode));
    std::memcpy(output + 6, &address, sizeof(address));
}

struct Relocation {
    detail::Instruction instruction;
    std::size_t source = 0, destination = 0, output_size = 0;
};

std::size_t relocated_size(const detail::Instruction &instruction) noexcept {
    switch (instruction.branch) {
    case detail::Branch::call:
        return x64 ? 16 : 5;
    case detail::Branch::jump:
        return x64 ? 14 : 5;
    case detail::Branch::conditional:
        return x64 ? 16 : 6;
    case detail::Branch::counter:
        return x64 ? 18 : 9;
    default:
        return instruction.size;
    }
}

Status allocate_trampoline(std::uintptr_t address, const std::uint8_t *signature, const Relocation *plan,
                           std::size_t count, std::size_t stolen, std::size_t relay_offset,
                           std::uint8_t *&output) noexcept {
    output = nullptr;
    if constexpr (!x64) {
        output = static_cast<std::uint8_t *>(
            VirtualAlloc(nullptr, allocation_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        return output ? Status::ok : Status::allocation_failed;
    } else {
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        detail::AddressRange range{reinterpret_cast<std::uintptr_t>(system.lpMinimumApplicationAddress),
                                   reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress) -
                                       allocation_size + 1};
        if (!range.constrain(address + 5, relay_offset, 0x80000000u, 0x7fffffffu))
            return Status::relocation_out_of_range;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &entry = plan[i];
            if (!entry.instruction.rip_relative)
                continue;
            std::int32_t displacement = 0;
            std::memcpy(&displacement, signature + entry.source + entry.instruction.displacement, 4);
            const auto destination =
                address + entry.source + entry.instruction.size + static_cast<std::uintptr_t>(displacement);
            if (destination >= address && destination < address + stolen)
                return Status::unsupported_instruction;
            if (!range.constrain(destination, entry.destination + entry.instruction.size, 0x7fffffffu,
                                 0x80000000u))
                return Status::relocation_out_of_range;
        }
        const auto allocated = detail::place_near(
            range, address, allocation_size, system.dwAllocationGranularity,
            [](std::uintptr_t at, detail::MemoryRegion &region) {
                MEMORY_BASIC_INFORMATION info{};
                if (!VirtualQuery(reinterpret_cast<void *>(at), &info, sizeof(info)))
                    return false;
                region = {reinterpret_cast<std::uintptr_t>(info.BaseAddress),
                          reinterpret_cast<std::uintptr_t>(info.AllocationBase), info.RegionSize,
                          info.State == MEM_FREE};
                return true;
            },
            [](std::uintptr_t at, std::size_t size) {
                return VirtualAlloc(reinterpret_cast<void *>(at), size, MEM_RESERVE | MEM_COMMIT,
                                    PAGE_READWRITE) != nullptr;
            });
        output = reinterpret_cast<std::uint8_t *>(allocated);
        return output ? Status::ok : Status::allocation_failed;
    }
}

Status relocate(const std::uint8_t *source, std::uintptr_t address, const Relocation *plan, std::size_t count,
                std::size_t stolen, std::uint8_t *trampoline) noexcept {
    for (std::size_t index = 0; index < count; ++index) {
        const auto &entry = plan[index];
        const auto &instruction = entry.instruction;
        auto *output = trampoline + entry.destination;
        const auto *input = source + entry.source;
        const auto next = address + entry.source + instruction.size;
        if (instruction.branch != detail::Branch::none) {
            std::int32_t displacement = 0;
            if (instruction.relative_size == 1)
                displacement = static_cast<std::int8_t>(input[instruction.relative]);
            else
                std::memcpy(&displacement, input + instruction.relative, 4);
            auto destination = next + static_cast<std::uintptr_t>(displacement);
            if (instruction.branch == detail::Branch::call && destination == next)
                return Status::unsupported_instruction;
            if (destination >= address && destination < address + stolen) {
                bool found = false;
                for (std::size_t i = 0; i < count; ++i)
                    if (address + plan[i].source == destination) {
                        destination = reinterpret_cast<std::uintptr_t>(trampoline + plan[i].destination);
                        found = true;
                        break;
                    }
                if (!found)
                    return Status::unsupported_instruction;
            }
            if (instruction.branch == detail::Branch::counter) {
                output[0] = input[0];
                output[1] = 2;
                output[2] = 0xeb;
                output[3] = x64 ? 14 : 5;
                if constexpr (x64)
                    absolute_jump(output + 4, destination);
                else
                    jump(output + 4, output + 4, reinterpret_cast<void *>(destination));
                continue;
            }
            if constexpr (x64) {
                if (instruction.branch == detail::Branch::call) {
                    const std::uint8_t opcode[] = {0xff, 0x15, 2, 0, 0, 0, 0xeb, 8};
                    const std::uint64_t target = destination;
                    std::memcpy(output, opcode, sizeof(opcode));
                    std::memcpy(output + 8, &target, sizeof(target));
                } else if (instruction.branch == detail::Branch::conditional) {
                    output[0] = static_cast<std::uint8_t>(0x70 | (instruction.condition ^ 1));
                    output[1] = 14;
                    absolute_jump(output + 2, destination);
                } else
                    absolute_jump(output, destination);
            } else {
                const std::size_t size = instruction.branch == detail::Branch::conditional ? 6 : 5;
                if (size == 6) {
                    output[0] = 0x0f;
                    output[1] = static_cast<std::uint8_t>(0x80 | instruction.condition);
                } else
                    output[0] = instruction.branch == detail::Branch::call ? 0xe8 : 0xe9;
                std::int32_t offset = 0;
                relative32(reinterpret_cast<std::uintptr_t>(output + size), destination, offset);
                std::memcpy(output + size - 4, &offset, 4);
            }
        } else {
            std::memcpy(output, input, instruction.size);
            if (instruction.rip_relative) {
                std::int32_t old = 0, offset = 0;
                std::memcpy(&old, input + instruction.displacement, 4);
                const auto destination = next + static_cast<std::uintptr_t>(old);
                if (destination >= address && destination < address + stolen)
                    return Status::unsupported_instruction;
                if (!relative32(reinterpret_cast<std::uintptr_t>(output + instruction.size), destination,
                                offset))
                    return Status::relocation_out_of_range;
                std::memcpy(output + instruction.displacement, &offset, 4);
            }
        }
    }
    return Status::ok;
}

}

const char *status_message(Status status) noexcept {
    switch (status) {
    case Status::ok:
        return "Success";
    case Status::invalid_argument:
        return "Invalid target, detour, or signature";
    case Status::already_prepared:
        return "Reset the hook before preparing it again";
    case Status::not_prepared:
        return "Prepare the hook first";
    case Status::signature_mismatch:
        return "Target bytes do not match the expected signature";
    case Status::unsupported_instruction:
        return "The entry contains an unsupported or incomplete instruction";
    case Status::inaccessible_memory:
        return "The address is not within one readable executable memory region";
    case Status::allocation_failed:
        return "Trampoline allocation failed";
    case Status::protection_failed:
        return "Memory protection could not be changed";
    case Status::protection_restore_failed:
        return "The bytes were written, but page protection could not be restored";
    case Status::cache_flush_failed:
        return "The bytes were written, but the instruction cache could not be flushed";
    case Status::relocation_out_of_range:
        return "A relative address cannot be represented from the trampoline";
    case Status::release_failed:
        return "Trampoline release failed";
    case Status::conflict:
        return "The target bytes or protection changed after preparation";
    case Status::capacity_exceeded:
        return "A batch supports at most 64 distinct hooks";
    case Status::overlapping_targets:
        return "A patch overlaps another hook's verified entry";
    case Status::cleanup_required:
        return "Finish pending protection or cache cleanup before batching this hook";
    }
    return "Unknown status";
}

Hook::~Hook() {
    reset();
}

Status Hook::prepare(void *target, void *detour) noexcept {
    if (prepared())
        return Status::already_prepared;
    if (!target || !detour)
        return Status::invalid_argument;
    DWORD protection = 0;
    if (!executable_range(target, 5, protection))
        return Status::inaccessible_memory;
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQuery(target, &info, sizeof(info)))
        return Status::inaccessible_memory;
    const auto offset =
        reinterpret_cast<std::uintptr_t>(target) - reinterpret_cast<std::uintptr_t>(info.BaseAddress);
    const auto available = std::min<std::size_t>(64, info.RegionSize - offset);
    std::array<std::uint8_t, 64> bytes{};
    if (!read_memory(target, bytes.data(), available))
        return Status::inaccessible_memory;
    std::size_t length = 0;
    while (length < 5) {
        detail::Instruction instruction;
        if (!detail::decode(bytes.data() + length, available - length, x64, instruction))
            return Status::unsupported_instruction;
        length += instruction.size;
        if (instruction.terminal && length < 5)
            return Status::unsupported_instruction;
    }
    return prepare(target, detour, bytes.data(), length);
}

Status Hook::prepare(void *target, void *detour, const std::uint8_t *expected, std::size_t size) noexcept {
    if (prepared())
        return Status::already_prepared;
    if (!target || !detour || !expected || size < 5 || size > expected_.size())
        return Status::invalid_argument;
    DWORD target_protection = 0, detour_protection = 0;
    if (!executable_range(target, size, target_protection) || !executable_range(detour, 1, detour_protection))
        return Status::inaccessible_memory;
    std::array<std::uint8_t, 64> signature{}, actual{};
    if (!read_memory(expected, signature.data(), size) || !read_memory(target, actual.data(), size))
        return Status::inaccessible_memory;
    if (std::memcmp(signature.data(), actual.data(), size) != 0)
        return Status::signature_mismatch;
    std::array<Relocation, 32> plan{};
    std::size_t length = 0, output_size = 0, count = 0;
    while (length < 5) {
        auto &entry = plan[count++];
        if (!detail::decode(signature.data() + length, size - length, x64, entry.instruction) ||
            entry.instruction.size > patch_.size() - length)
            return Status::unsupported_instruction;
        entry.source = length;
        entry.destination = output_size;
        entry.output_size = relocated_size(entry.instruction);
        length += entry.instruction.size;
        output_size += entry.output_size;
        if (entry.instruction.terminal && length < 5)
            return Status::unsupported_instruction;
    }
    const auto address = reinterpret_cast<std::uintptr_t>(target);
    const auto destination = reinterpret_cast<std::uintptr_t>(detour);
    if (destination >= address && destination < address + length)
        return Status::invalid_argument;
    std::uint8_t *trampoline = nullptr;
    const auto placement = allocate_trampoline(address, signature.data(), plan.data(), count, length,
                                               output_size + (x64 ? 14 : 5), trampoline);
    if (placement != Status::ok)
        return placement;
    const auto release = [](std::uint8_t *memory) { VirtualFree(memory, 0, MEM_RELEASE); };
    std::unique_ptr<std::uint8_t, decltype(release)> owner(trampoline, release);
    const auto relocated = relocate(signature.data(), address, plan.data(), count, length, trampoline);
    if (relocated != Status::ok)
        return relocated;
    auto *relay = trampoline + output_size + (x64 ? 14 : 5);
    if constexpr (x64) {
        absolute_jump(trampoline + output_size, address + length);
        absolute_jump(relay, destination);
        std::int32_t offset = 0;
        if (!relative32(address + 5, reinterpret_cast<std::uintptr_t>(relay), offset))
            return Status::relocation_out_of_range;
    } else
        jump(trampoline + output_size, trampoline + output_size,
             static_cast<std::uint8_t *>(target) + length);
    DWORD ignored = 0;
    if (!VirtualProtect(trampoline, allocation_size, PAGE_EXECUTE_READ, &ignored))
        return Status::protection_failed;
    if (!FlushInstructionCache(GetCurrentProcess(), trampoline, allocation_size))
        return Status::cache_flush_failed;
    expected_ = signature;
    patch_.fill(0x90);
    jump(patch_.data(), target, x64 ? relay : detour);
    target_ = target;
    trampoline_ = owner.release();
    signature_size_ = size;
    patch_size_ = length;
    protection_ = target_protection;
    return Status::ok;
}

Status Hook::verify_bytes() const noexcept {
    if (!prepared())
        return Status::not_prepared;
    std::array<std::uint8_t, 64> actual{};
    DWORD protection = 0;
    if (!executable_range(target_, signature_size_, protection) ||
        !read_memory(target_, actual.data(), signature_size_))
        return Status::inaccessible_memory;
    const auto *before = enabled_ ? patch_.data() : expected_.data();
    if (std::memcmp(actual.data(), before, patch_size_) != 0 ||
        std::memcmp(actual.data() + patch_size_, expected_.data() + patch_size_,
                    signature_size_ - patch_size_) != 0 ||
        protection != (restore_pending_ ? PAGE_EXECUTE_READWRITE : protection_))
        return Status::conflict;
    return Status::ok;
}

Status Hook::validate() const noexcept {
    const auto status = verify_bytes();
    return status == Status::ok && cleanup_pending() ? Status::cleanup_required : status;
}

Status Hook::write(bool enable) noexcept {
    const auto status = verify_bytes();
    if (status != Status::ok)
        return status;
    if (enable == enabled_ && !restore_pending_ && !cache_pending_)
        return Status::ok;
    DWORD ignored = 0;
    if (!VirtualProtect(target_, patch_size_, PAGE_EXECUTE_READWRITE, &ignored))
        return Status::protection_failed;
    restore_pending_ = true;
    std::memcpy(target_, enable ? patch_.data() : expected_.data(), patch_size_);
    enabled_ = enable;
    cache_pending_ = !FlushInstructionCache(GetCurrentProcess(), target_, patch_size_);
    if (!VirtualProtect(target_, patch_size_, protection_, &ignored))
        return Status::protection_restore_failed;
    restore_pending_ = false;
    return cache_pending_ ? Status::cache_flush_failed : Status::ok;
}

Status Hook::enable() noexcept {
    return write(true);
}
Status Hook::disable() noexcept {
    return write(false);
}

Status Hook::reset() noexcept {
    if (!prepared())
        return Status::ok;
    if (enabled_ || restore_pending_ || cache_pending_) {
        const auto status = disable();
        if (status != Status::ok)
            return status;
    }
    if (!VirtualFree(trampoline_, 0, MEM_RELEASE))
        return Status::release_failed;
    target_ = trampoline_ = nullptr;
    signature_size_ = patch_size_ = 0;
    protection_ = 0;
    return Status::ok;
}

Status Batch::queue(Hook &hook, bool enable) noexcept {
    if (!hook.prepared())
        return Status::not_prepared;
    for (std::size_t i = 0; i < size_; ++i)
        if (entries_[i].hook == &hook) {
            entries_[i].enable = enable;
            return Status::ok;
        }
    if (size_ == entries_.size())
        return Status::capacity_exceeded;
    entries_[size_++] = {&hook, enable};
    return Status::ok;
}

BatchResult Batch::commit() noexcept {
    return detail::commit_changes(
        size_,
        [&](std::size_t index) {
            const auto &hook = *entries_[index].hook;
            const auto status = hook.validate();
            if (status != Status::ok)
                return status;
            const auto start = reinterpret_cast<std::uintptr_t>(hook.target_);
            for (std::size_t i = 0; i < index; ++i) {
                const auto &other = *entries_[i].hook;
                const auto base = reinterpret_cast<std::uintptr_t>(other.target_);
                if ((start < base + other.signature_size_ && base < start + hook.patch_size_) ||
                    (base < start + hook.signature_size_ && start < base + other.patch_size_))
                    return Status::overlapping_targets;
            }
            return Status::ok;
        },
        [&](std::size_t index) { return entries_[index].hook->enabled(); },
        [&](std::size_t index, bool rollback, bool previous) {
            auto &entry = entries_[index];
            return entry.hook->write(rollback ? previous : entry.enable);
        });
}

}
