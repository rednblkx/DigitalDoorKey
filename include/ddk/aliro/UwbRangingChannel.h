#pragma once
#include "ddk/Span.h"
#include <array>
#include <cstdint>
#include <functional>

namespace ddk::aliro {

class UwbRangingChannel {
public:
    virtual ~UwbRangingChannel() = default;

    virtual void set_sender(
        std::function<bool(ddk::span<const uint8_t> frame)> send) = 0;

    virtual void arm(uint32_t session_id, ddk::span<const uint8_t> ursk,
                     const std::array<uint8_t, 2>& selected_version) = 0;

    virtual void handle_frame(ddk::span<const uint8_t> frame) = 0;

    virtual void poll() {}

    virtual bool ranging_active() const { return false; }

    virtual void stop() = 0;
};

}  // namespace ddk::aliro
