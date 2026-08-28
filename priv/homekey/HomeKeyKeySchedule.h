#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include "ddk/Span.h"

// Stateless. Construct on the stack where needed.
class HomeKeyKeySchedule {
public:
    struct SessionInput {
        ddk::span<const uint8_t> reader_pk_x;
        ddk::span<const uint8_t> reader_identifier;
        ddk::span<const uint8_t> reader_eph_x;
        ddk::span<const uint8_t> endpoint_eph_x;
        ddk::span<const uint8_t> transaction_id;
        std::array<uint8_t,2> version;
        std::array<uint8_t,2> flags;
    };

    // FAST: 58-byte cryptogram material. Caller compares first 16 bytes.
    std::vector<uint8_t> derive_fast_material(
        const SessionInput& input,
        ddk::span<const uint8_t> endpoint_pk_x,
        ddk::span<const uint8_t> persistent_key);

    // STANDARD: persistent (32) + volatile (48 → ScbSecureChannel)
    struct StandardResult {
        std::array<uint8_t,32> persistent_key;
        std::vector<uint8_t> volatile_key;
    };
    StandardResult derive_standard(
        const SessionInput& input,
        ddk::span<const uint8_t,32> derived_key);
};
