#include "CoseSign1.h"
#include "CommonCryptoUtils.h"
#include "DDKLogging.h"
#include <cbor.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <cstring>

#if defined(CONFIG_IDF_CMAKE)
#include <sodium/crypto_sign_ed25519.h>
#else
#include "sodium.h"
#endif

namespace {

constexpr const char* TAG = "CoseSign1";

bool verify_es256(
    const CoseSign1::Parsed& parsed,
    ddk::span<const uint8_t> issuer_public_key,
    ddk::span<const uint8_t> external_aad)
{
    if (issuer_public_key.size() != 65) {
        LOG(E, "CoseSign1: ES256 key must be 65 bytes, got %zu",
            issuer_public_key.size());
        return false;
    }
    if (parsed.signature.size() != 64) {
        LOG(E, "CoseSign1: ES256 signature must be 64 bytes (r||s), got %zu",
            parsed.signature.size());
        return false;
    }

    auto sig_struct = CoseSign1::build_sig_structure(
        parsed.protected_headers_encoded, external_aad, parsed.payload);

    uint8_t hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               sig_struct.data(), sig_struct.size(), hash);

    CommonCryptoUtils::EcpGroupGuard grp;
    CommonCryptoUtils::EcpPointGuard Q;
    CommonCryptoUtils::MpiGuard r, s;

    mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
    int ret = mbedtls_ecp_point_read_binary(grp, Q,
        issuer_public_key.data(), issuer_public_key.size());
    if (ret != 0) {
        LOG(E, "CoseSign1: failed to read P-256 public key: %d", ret);
        return false;
    }

    mbedtls_mpi_read_binary(r, parsed.signature.data(), 32);
    mbedtls_mpi_read_binary(s, parsed.signature.data() + 32, 32);

    ret = mbedtls_ecdsa_verify(grp, hash, 32, Q, r, s);
    if (ret != 0) {
        LOG(E, "CoseSign1: ES256 verify failed: %d", ret);
        return false;
    }
    return true;
}

bool verify_ed25519(
    const CoseSign1::Parsed& parsed,
    ddk::span<const uint8_t> issuer_public_key,
    ddk::span<const uint8_t> external_aad)
{
    if (issuer_public_key.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
        LOG(E, "CoseSign1: Ed25519 key must be %d bytes, got %zu",
            (int)crypto_sign_ed25519_PUBLICKEYBYTES, issuer_public_key.size());
        return false;
    }
    if (parsed.signature.size() != crypto_sign_ed25519_BYTES) {
        LOG(E, "CoseSign1: Ed25519 signature must be %d bytes, got %zu",
            (int)crypto_sign_ed25519_BYTES, parsed.signature.size());
        return false;
    }

    auto sig_struct = CoseSign1::build_sig_structure(
        parsed.protected_headers_encoded, external_aad, parsed.payload);

    int ret = crypto_sign_ed25519_verify_detached(
        parsed.signature.data(),
        sig_struct.data(), sig_struct.size(),
        issuer_public_key.data());
    if (ret != 0) {
        LOG(E, "CoseSign1: Ed25519 verify failed: %d", ret);
        return false;
    }
    return true;
}

} // namespace

// --- Public verify overloads ---

std::optional<CoseSign1::Parsed> CoseSign1::parse(ddk::span<const uint8_t> cbor)
{
    CborParser parser;
    CborValue it;
    if (cbor_parser_init(cbor.data(), cbor.size(), 0, &parser, &it)
        != CborNoError)
        return std::nullopt;
    if (!cbor_value_is_array(&it))
        return std::nullopt;
    return parse_from_iterator(&it);
}

std::optional<CoseSign1::Parsed> CoseSign1::parse_from_iterator(CborValue* it)
{
      if (!cbor_value_is_array(it))
        return std::nullopt;

    CborValue elem;
    if (cbor_value_enter_container(it, &elem) != CborNoError)
        return std::nullopt;

    Parsed result;

    // --- Element 1: protected headers (bstr) ---
    if (!cbor_value_is_byte_string(&elem))
        return std::nullopt;
    {
        size_t len = 0;
        if (cbor_value_get_string_length(&elem, &len) != CborNoError)
            return std::nullopt;
        result.protected_headers_encoded.resize(len);
        cbor_value_copy_byte_string(&elem, result.protected_headers_encoded.data(),
                                    &len, nullptr);
    }
    if (cbor_value_advance(&elem) != CborNoError)
        return std::nullopt;

    // --- Element 2: unprotected headers (map) ---
    if (!cbor_value_is_map(&elem))
        return std::nullopt;
    {
        CborValue map_it;
        if (cbor_value_enter_container(&elem, &map_it) != CborNoError)
            return std::nullopt;
        while (!cbor_value_at_end(&map_it)) {
            if (cbor_value_is_integer(&map_it)) {
                int key = 0;
                cbor_value_get_int(&map_it, &key);
                if (cbor_value_advance(&map_it) != CborNoError)
                    return std::nullopt;
                if (key == 4 && cbor_value_is_byte_string(&map_it)) {
                    size_t ilen = 0;
                    if (cbor_value_get_string_length(&map_it, &ilen) != CborNoError)
                        return std::nullopt;
                    std::vector<uint8_t> id(ilen);
                    cbor_value_copy_byte_string(&map_it, id.data(), &ilen, nullptr);
                    result.issuer_id = std::move(id);
                }
            }
            if (cbor_value_at_end(&map_it)) break;
            if (cbor_value_advance(&map_it) != CborNoError)
                return std::nullopt;
        }
        if (cbor_value_leave_container(&elem, &map_it) != CborNoError)
            return std::nullopt;
    }

    // --- Element 3: payload (bstr) ---
    if (!cbor_value_is_byte_string(&elem))
        return std::nullopt;
    {
        size_t len = 0;
        if (cbor_value_get_string_length(&elem, &len) != CborNoError)
            return std::nullopt;
        result.payload.resize(len);
        cbor_value_copy_byte_string(&elem, result.payload.data(), &len, nullptr);
    }
    if (cbor_value_advance(&elem) != CborNoError)   // advance past primitive: OK
        return std::nullopt;

    // --- Element 4: signature (bstr) ---
    if (!cbor_value_is_byte_string(&elem))
        return std::nullopt;
    {
        size_t len = 0;
        if (cbor_value_get_string_length(&elem, &len) != CborNoError)
            return std::nullopt;
        result.signature.resize(len);
        cbor_value_copy_byte_string(&elem, result.signature.data(), &len, nullptr);
    }

    {
        CborParser ph_parser;
        CborValue ph_it;
        if (cbor_parser_init(result.protected_headers_encoded.data(),
                             result.protected_headers_encoded.size(),
                             0, &ph_parser, &ph_it) == CborNoError &&
            cbor_value_is_map(&ph_it))
        {
            size_t map_len = 0;
            cbor_value_get_map_length(&ph_it, &map_len);
            CborValue map_it;
            if (cbor_value_enter_container(&ph_it, &map_it) == CborNoError) {
                for (size_t i = 0; i < map_len && !cbor_value_at_end(&map_it);
                     ++i) {
                    if (cbor_value_is_integer(&map_it)) {
                        int key = 0;
                        cbor_value_get_int(&map_it, &key);
                        if (cbor_value_advance(&map_it) != CborNoError) break;
                        if (key == 1 && cbor_value_is_integer(&map_it)) {
                            cbor_value_get_int(&map_it, &result.algorithm);
                        }
                    }
                    if (cbor_value_at_end(&map_it)) break;
                    if (cbor_value_advance(&map_it) != CborNoError) break;
                }
            }
        }
    }

    return result;
}

std::vector<uint8_t> CoseSign1::build_sig_structure(
    ddk::span<const uint8_t> protected_headers,
    ddk::span<const uint8_t> external_aad,
    ddk::span<const uint8_t> payload)
{
    // SigStructure = ["Signature1", protected_headers, external_aad, payload]
    uint8_t buf[4096];
    CborEncoder enc;
    CborEncoder array;

    cbor_encoder_init(&enc, buf, sizeof(buf), 0);
    cbor_encoder_create_array(&enc, &array, 4);
    cbor_encode_text_stringz(&array, "Signature1");
    cbor_encode_byte_string(&array,
        protected_headers.data(), protected_headers.size());
    cbor_encode_byte_string(&array,
        external_aad.data(), external_aad.size());
    cbor_encode_byte_string(&array,
        payload.data(), payload.size());
    cbor_encoder_close_container(&enc, &array);

    size_t encoded = cbor_encoder_get_buffer_size(&enc, buf);
    return std::vector<uint8_t>(buf, buf + encoded);
}

bool CoseSign1::verify(
    const Parsed& parsed,
    CoseAlgorithm expected,
    ddk::span<const uint8_t> issuer_public_key,
    ddk::span<const uint8_t> external_aad)
{
    if (parsed.algorithm != static_cast<int>(expected)) {
        LOG(E, "CoseSign1: algorithm mismatch — expected %d, got %d",
            static_cast<int>(expected), parsed.algorithm);
        return false;
    }
    switch (expected) {
        case CoseAlgorithm::ES256:
            return verify_es256(parsed, issuer_public_key, external_aad);
        case CoseAlgorithm::Ed25519:
            return verify_ed25519(parsed, issuer_public_key, external_aad);
    }
    return false;
}

bool CoseSign1::verify(
    const Parsed& parsed,
    ddk::span<const uint8_t> issuer_public_key,
    ddk::span<const uint8_t> external_aad)
{
    if (parsed.algorithm == static_cast<int>(CoseAlgorithm::ES256)) {
        return verify_es256(parsed, issuer_public_key, external_aad);
    }
    if (parsed.algorithm == static_cast<int>(CoseAlgorithm::Ed25519)) {
        return verify_ed25519(parsed, issuer_public_key, external_aad);
    }
    LOG(E, "CoseSign1: unsupported algorithm %d", parsed.algorithm);
    return false;
}
