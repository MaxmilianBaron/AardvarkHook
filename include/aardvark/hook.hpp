#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <mutex>
#include <shared_mutex>

namespace aardvark::hook {

enum class Status {
    ok,
    invalid_argument,
    already_prepared,
    not_prepared,
    signature_mismatch,
    unsupported_instruction,
    inaccessible_memory,
    allocation_failed,
    protection_failed,
    protection_restore_failed,
    cache_flush_failed,
    conflict,
    relocation_out_of_range,
    release_failed,
    capacity_exceeded,
    overlapping_targets,
    cleanup_required
};

const char *status_message(Status) noexcept;

class ExecutionGate {
    std::shared_mutex mutex_;

  public:
    [[nodiscard]] std::shared_lock<std::shared_mutex> enter() {
        return std::shared_lock<std::shared_mutex>(mutex_);
    }
    [[nodiscard]] std::unique_lock<std::shared_mutex> update() {
        return std::unique_lock<std::shared_mutex>(mutex_);
    }
};

class Hook {
    friend class Batch;
    void *target_ = nullptr;
    void *trampoline_ = nullptr;
    std::array<std::uint8_t, 64> expected_{};
    std::array<std::uint8_t, 32> patch_{};
    std::size_t signature_size_ = 0;
    std::size_t patch_size_ = 0;
    unsigned long protection_ = 0;
    bool enabled_ = false;
    bool restore_pending_ = false;
    bool cache_pending_ = false;
    Status verify_bytes() const noexcept;
    Status write(bool enable) noexcept;

  public:
    Hook() = default;
    ~Hook();
    Hook(const Hook &) = delete;
    Hook &operator=(const Hook &) = delete;
    Hook(Hook &&) = delete;
    Hook &operator=(Hook &&) = delete;

    Status prepare(void *target, void *detour) noexcept;
    Status prepare(void *target, void *detour, const std::uint8_t *expected, std::size_t size) noexcept;
    Status prepare(void *target, void *detour, std::initializer_list<std::uint8_t> expected) noexcept {
        return prepare(target, detour, expected.begin(), expected.size());
    }
    Status enable() noexcept;
    Status disable() noexcept;
    Status reset() noexcept;
    Status validate() const noexcept;
    bool cleanup_pending() const noexcept {
        return restore_pending_ || cache_pending_;
    }
    bool prepared() const noexcept {
        return trampoline_ != nullptr;
    }
    bool enabled() const noexcept {
        return enabled_;
    }
    std::size_t patch_size() const noexcept {
        return patch_size_;
    }
    void *original() const noexcept {
        return trampoline_;
    }
    template <class Function> Function original_as() const noexcept {
        return reinterpret_cast<Function>(original());
    }
};

struct BatchResult {
    static constexpr std::size_t no_index = static_cast<std::size_t>(-1);
    Status status = Status::ok;
    std::size_t index = no_index;
    Status rollback_status = Status::ok;
    std::size_t rollback_index = no_index;
    explicit operator bool() const noexcept {
        return status == Status::ok;
    }
};

class Batch {
    struct Entry {
        Hook *hook = nullptr;
        bool enable = false;
    };
    std::array<Entry, 64> entries_{};
    std::size_t size_ = 0;

  public:
    Status queue(Hook &, bool enable) noexcept;
    BatchResult commit() noexcept;
    void clear() noexcept {
        size_ = 0;
    }
    std::size_t size() const noexcept {
        return size_;
    }
};

}
