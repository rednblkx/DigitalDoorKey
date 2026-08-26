#pragma once
#include "cbor.h"
#include "ddk/Span.h"
#include <cstdint>
#include <optional>
#include <vector>

// COSE Sign1 (RFC 8152):
// [protected_headers: bstr, unprotected_headers: map, payload: bstr, signature: bstr]
//
// Two algorithm variants used in this library:
//   ES256  (alg -7): ECDSA P-256 + SHA-256, signature = raw r||s (64 bytes)
//                     — Aliro issuerAuth (document verification)
//   Ed25519 (alg -8): Ed25519, signature = 64 bytes
//                     — HomeKey attestation issuerAuth

enum class CoseAlgorithm : int {
    ES256   = -7,
    Ed25519 = -8,
};

class CoseSign1 {
public:
    struct Parsed {
        std::vector<uint8_t> protected_headers_encoded;  // raw bstr
        std::vector<uint8_t> payload;                    // raw bstr (may contain tag 24)
        std::vector<uint8_t> signature;                  // 64 bytes for both variants
        std::optional<std::vector<uint8_t>> issuer_id;   // unprotected header key 4
        int algorithm = 0;  // protected header key 1 (alg), negative value
    };

    static std::optional<Parsed> parse(ddk::span<const uint8_t> cbor);
    static std::optional<Parsed> parse_from_iterator(CborValue* it);

    // Build SigStructure = ["Signature1", protected, external_aad, payload]
    // Identical for both algorithms.
    static std::vector<uint8_t> build_sig_structure(
        ddk::span<const uint8_t> protected_headers,
        ddk::span<const uint8_t> external_aad,
        ddk::span<const uint8_t> payload);

    // Verify — dispatches on parsed.algorithm.
    //   ES256:   issuer_public_key = 65-byte uncompressed P-256 point
    //   Ed25519: issuer_public_key = 32-byte Ed25519 public key
    // Returns false for any algorithm other than -7 / -8.
    static bool verify(
        const Parsed& parsed,
        ddk::span<const uint8_t> issuer_public_key,
        ddk::span<const uint8_t> external_aad = {});

    // Verify with explicit expected algorithm — use when the caller
    // knows which algorithm the issuer must have used.
    static bool verify(
        const Parsed& parsed,
        CoseAlgorithm expected,
        ddk::span<const uint8_t> issuer_public_key,
        ddk::span<const uint8_t> external_aad = {});
};
