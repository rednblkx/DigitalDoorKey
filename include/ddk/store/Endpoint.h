#pragma once
#include <cstdint>
#include <optional>
#include <vector>
#include "ddk/session/Flow.h"

namespace ddk {

enum class KeyType : uint8_t { Secp256r1 = 2 };

// Aliro-specific per-endpoint state accumulated across transactions.
struct AliroEndpointData {
    std::vector<uint8_t> key_slot;                     // AUTH1 tag 0x4E (8B)
    std::optional<uint16_t> signaling_bitmask;         // AUTH1 tag 0x5E
    std::vector<uint8_t> credential_signed_timestamp;  // AUTH1 tag 0x91 (20B tdate)
    std::vector<uint8_t> revocation_signed_timestamp;  // AUTH1 tag 0x92 (20B tdate)
    ddk::KeyFlow last_flow = ddk::kFlowNext;                     // last flow that authenticated

    bool empty() const {
        return key_slot.empty() && !signaling_bitmask &&
               credential_signed_timestamp.empty() &&
               revocation_signed_timestamp.empty() && last_flow == ddk::kFlowNext;
    }
};

struct Endpoint {
    std::vector<uint8_t> id;              // "endpointId"
    std::vector<uint8_t> public_key;      // "publicKey"      65B uncompressed
    std::vector<uint8_t> public_key_x;    // "endpoint_key_x" 32B
    std::vector<uint8_t> persistent_key;  // "persistent_key" 32B
    uint32_t used_at = 0;                 // "last_used_at"
    uint8_t  counter = 0;                 // "counter"        width preserved
    KeyType  key_type = KeyType::Secp256r1;
    AliroEndpointData aliro;
};
}
