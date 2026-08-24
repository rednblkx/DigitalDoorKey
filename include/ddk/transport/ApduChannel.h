#pragma once
#include "ddk/Span.h"
#include <cstdint>
#include <vector>

namespace ddk {

enum class TransportKind : uint8_t { Nfc, Ble };

struct ApduResponse {
    std::vector<uint8_t> data;   // body, SW stripped
    uint8_t sw1 = 0;
    uint8_t sw2 = 0;
    bool ok()   const { return sw1 == 0x90 && sw2 == 0x00; }
    bool more() const { return sw1 == 0x61; }
};

class ApduChannel {
public:
    virtual ~ApduChannel() = default;
    virtual TransportKind kind() const = 0;
    virtual size_t max_command_payload() const = 0;
    virtual ApduResponse transceive(ddk::span<const uint8_t> capdu) = 0;
    virtual ApduResponse transceive_full(
        ddk::span<const uint8_t> capdu,
        bool skip_response_chaining = false) = 0;
};

}  // namespace ddk
