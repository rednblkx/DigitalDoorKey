#pragma once
#include "ddk/Span.h"
#include <cstdint>
#include <vector>

namespace ddk {

enum class TransportKind : uint8_t { Nfc, Ble };

struct ApduCommand {
    uint8_t cla = 0x80;
    uint8_t ins = 0;
    uint8_t p1 = 0;
    uint8_t p2 = 0;
    std::vector<uint8_t> data;
    uint16_t ne = 0;   // expected response length; 0 = none, 256 max short-form

    // Serializes with correct ISO 7816-4 case encoding:
    // case 1 (no data, no ne), case 2S/2E (ne only), case 3S/3E (data only),
    // case 4S/4E (data + ne). Short form unless forced or fields exceed it.
    std::vector<uint8_t> to_bytes(bool force_extended = false) const;
};

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

    // Single-shot. No chaining. Caller owns SW handling.
    virtual ApduResponse transceive(ddk::span<const uint8_t> capdu) = 0;

    // Full exchange with command chaining (CLA 0x10 chunks) and
    // response chaining (GET RESPONSE reassembly).
    // skip_response_chaining: return first response without issuing 
    // GET RESPONSE.
    virtual ApduResponse transceive_full(
        const ApduCommand& command,
        bool skip_response_chaining = false,
        size_t max_command_chunk = 255) = 0;
};
}  // namespace ddk
