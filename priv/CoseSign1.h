#pragma once
#include "ddk/Span.h"
#include <cstdint>
#include <optional>
#include <vector>

// COSE Sign1 (RFC 8152):
// [protected_headers: bstr, unprotected_headers: map, payload: bstr, signature: bstr]
// ES256: algorithm -7, ECDSA P-256 SHA-256, signature = raw r‖s (64 bytes)

class CoseSign1 {
public:
    struct Parsed {
        std::vector<uint8_t> protected_headers_encoded;  // raw bstr
        std::vector<uint8_t> payload;                    // raw bstr (may contain tag 24)
        std::vector<uint8_t> signature;                  // raw r‖s (64 bytes for ES256)
        std::optional<std::vector<uint8_t>> issuer_id;  // unprotected header key 4
        int algorithm = 0;  // protected header key 1 (expected -7 = ES256)
    };

    // Parse a COSE Sign1 from CBOR bytes.
    static std::optional<Parsed> parse(ddk::span<const uint8_t> cbor);

    // Build SigStructure = ["Signature1", protected, external_aad, payload]
    static std::vector<uint8_t> build_sig_structure(
        ddk::span<const uint8_t> protected_headers,
        ddk::span<const uint8_t> external_aad,
        ddk::span<const uint8_t> payload);

    // Verify ES256 signature. issuer_public_key = 65-byte uncompressed P-256.
    static bool verify(
        const Parsed& parsed,
        ddk::span<const uint8_t, 65> issuer_public_key,
        ddk::span<const uint8_t> external_aad = {});
};
