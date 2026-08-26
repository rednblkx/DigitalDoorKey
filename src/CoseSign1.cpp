#include "CoseSign1.h"
#include "CommonCryptoUtils.h"
#include "DDKLogging.h"
#include <cbor.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <cstring>

constexpr const char* TAG = "CoseSign1";

// --- Parse ---

std::optional<CoseSign1::Parsed> CoseSign1::parse(ddk::span<const uint8_t> cbor)
{
    CborParser parser;
    CborValue it;

    if (cbor_parser_init(cbor.data(), cbor.size(), 0, &parser, &it) != CborNoError)
        return std::nullopt;

    // Top-level must be a 4-element array
    if (!cbor_value_is_array(&it))
        return std::nullopt;

    size_t array_len = 0;
    if (cbor_value_get_array_length(&it, &array_len) != CborNoError || array_len != 4)
        return std::nullopt;

    CborValue elem;
    if (cbor_value_enter_container(&it, &elem) != CborNoError)
        return std::nullopt;

    Parsed result;

    // Element 1: protected headers (bstr)
    if (!cbor_value_is_byte_string(&elem))
        return std::nullopt;
    {
        size_t len = 0;
        cbor_value_get_string_length(&elem, &len);
        result.protected_headers_encoded.resize(len);
        cbor_value_copy_byte_string(&elem, result.protected_headers_encoded.data(),
                                     &len, nullptr);
    }
    cbor_value_advance(&elem);

    // Element 2: unprotected headers (map)
    if (cbor_value_is_map(&elem)) {
        size_t map_len = 0;
        cbor_value_get_map_length(&elem, &map_len);
        CborValue map_it;
        cbor_value_enter_container(&elem, &map_it);
        for (size_t i = 0; i < map_len; ++i) {
            int key = 0;
            cbor_value_get_int(&map_it, &key);
            cbor_value_advance(&map_it);
            if (key == 4 && cbor_value_is_byte_string(&map_it)) {
                // issuer_id (header label 4)
                size_t ilen = 0;
                cbor_value_get_string_length(&map_it, &ilen);
                std::vector<uint8_t> id(ilen);
                cbor_value_copy_byte_string(&map_it, id.data(), &ilen, nullptr);
                result.issuer_id = std::move(id);
            }
            cbor_value_advance(&map_it);
        }
        cbor_value_leave_container(&elem, &map_it);
    }
    cbor_value_advance(&elem);

    // Element 3: payload (bstr)
    if (!cbor_value_is_byte_string(&elem))
        return std::nullopt;
    {
        size_t len = 0;
        cbor_value_get_string_length(&elem, &len);
        result.payload.resize(len);
        cbor_value_copy_byte_string(&elem, result.payload.data(), &len, nullptr);
    }
    cbor_value_advance(&elem);

    // Element 4: signature (bstr)
    if (!cbor_value_is_byte_string(&elem))
        return std::nullopt;
    {
        size_t len = 0;
        cbor_value_get_string_length(&elem, &len);
        result.signature.resize(len);
        cbor_value_copy_byte_string(&elem, result.signature.data(), &len, nullptr);
    }
    cbor_value_advance(&elem);

    cbor_value_leave_container(&it, &elem);

    // Decode protected headers (CBOR map inside the bstr) to extract algorithm
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
            cbor_value_enter_container(&ph_it, &map_it);
            for (size_t i = 0; i < map_len; ++i) {
                int key = 0;
                cbor_value_get_int(&map_it, &key);
                cbor_value_advance(&map_it);
                if (key == 1 && cbor_value_is_integer(&map_it)) {
                    cbor_value_get_int(&map_it, &result.algorithm);
                }
                cbor_value_advance(&map_it);
            }
            cbor_value_leave_container(&ph_it, &map_it);
        }
    }

    LOG(D, "CoseSign1 parsed: alg=%d, payload=%zu bytes, sig=%zu bytes, issuer_id=%s",
        result.algorithm, result.payload.size(), result.signature.size(),
        result.issuer_id ? "present" : "absent");

    return result;
}

// --- Build SigStructure ---

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

// --- Verify ---

bool CoseSign1::verify(
    const Parsed& parsed,
    ddk::span<const uint8_t, 65> issuer_public_key,
    ddk::span<const uint8_t> external_aad)
{
    if (parsed.algorithm != -7) {
        LOG(E, "CoseSign1: unsupported algorithm %d (expected -7 = ES256)",
            parsed.algorithm);
        return false;
    }
    if (parsed.signature.size() != 64) {
        LOG(E, "CoseSign1: signature must be 64 bytes (r||s), got %zu",
            parsed.signature.size());
        return false;
    }

    // Build SigStructure
    auto sig_struct = build_sig_structure(
        parsed.protected_headers_encoded, external_aad, parsed.payload);

    // SHA-256 hash of SigStructure
    uint8_t hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
              sig_struct.data(), sig_struct.size(), hash);

    // ECDSA verify: r = first 32 bytes, s = last 32 bytes
    CommonCryptoUtils::EcpGroupGuard grp;
    CommonCryptoUtils::EcpPointGuard Q;
    CommonCryptoUtils::MpiGuard r, s;

    mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
    int ret = mbedtls_ecp_point_read_binary(grp, Q,
        issuer_public_key.data(), issuer_public_key.size());
    if (ret != 0) {
        LOG(E, "CoseSign1: failed to read public key: %d", ret);
        return false;
    }

    mbedtls_mpi_read_binary(r, parsed.signature.data(), 32);
    mbedtls_mpi_read_binary(s, parsed.signature.data() + 32, 32);

    ret = mbedtls_ecdsa_verify(grp, hash, 32, Q, r, s);
    if (ret != 0) {
        LOG(E, "CoseSign1: ECDSA verify failed: %d", ret);
        return false;
    }

    LOG(D, "CoseSign1: ES256 verification successful");
    return true;
}
