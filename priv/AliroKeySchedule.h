#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include "ddk/Span.h"

class AliroKeySchedule {
public:
    struct SessionInput {
        ddk::span<const uint8_t> reader_pk_x;
        ddk::span<const uint8_t> reader_identifier;
        ddk::span<const uint8_t> reader_eph_x;
        ddk::span<const uint8_t> endpoint_eph_x;
        ddk::span<const uint8_t> transaction_id;
        std::array<uint8_t,2> version;
        std::array<uint8_t,2> flags;
        ddk::span<const uint8_t> fci_proprietary;
        uint8_t interface;
        ddk::span<const uint8_t> auth0_info_suffix;
    };

    struct FastResult {
        std::array<uint8_t,32> cryptogram_sk;
        std::array<uint8_t,32> exchange_sk_reader;
        std::array<uint8_t,32> exchange_sk_device;
        std::array<uint8_t,32> uwb_ranging_sk;
    };
    FastResult derive_fast(
        const SessionInput& input,
        ddk::span<const uint8_t> endpoint_pk_x,
        ddk::span<const uint8_t> persistent_key);

    // Called BEFORE AUTH1 response parsing.
    // endpoint_pk_x is NOT in the volatile salt.
    struct VolatileResult {
        std::array<uint8_t,32> exchange_sk_reader;
        std::array<uint8_t,32> exchange_sk_device;
    };
    VolatileResult derive_volatile(
        const SessionInput& input,
        ddk::span<const uint8_t,32> derived_key);

    // Called AFTER endpoint lookup + signature verify.
    // endpoint_pk_x IS in the persistent salt.
    std::array<uint8_t,32> derive_persistent(
        const SessionInput& input,
        ddk::span<const uint8_t,32> derived_key,
        ddk::span<const uint8_t> endpoint_pk_x);
};
