#include "homekey/HKStandardAuth.h"
#include "homekey/HomeKeyKeySchedule.h"
#include "ddk/store/CredentialStore.h"
#include "ddk/store/ReaderIdentity.h"
#include "CommonCryptoUtils.h"
#include "ScbSecureChannel.h"
#include "x963kdf.h"
#include "simple_tlv.hpp"
#include "TLV8.hpp"
#include "DDKLogging.h"
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/md.h>
#include <mbedtls/ecp.h>
#include <iterator>
#include <memory>
#include <vector>

constexpr const char* TAG = "HKStandardAuth";

std::vector<uint8_t> HomeKeyStdAuth::buildAuth1SignatureInput()
{
    auto& t = session_.transcript();

    std::vector<uint8_t> tlv;
    tlv.reserve(t.reader_identifier.size() + t.endpoint_eph_x.size() +
                t.reader_eph_x.size() + t.transaction_id.size() + 15);

    auto t1 = simple_tlv(0x4D, t.reader_identifier);
    std::copy(t1.begin(), t1.end(), std::back_inserter(tlv));
    auto t2 = simple_tlv(0x86, t.endpoint_eph_x);
    std::copy(t2.begin(), t2.end(), std::back_inserter(tlv));
    auto t3 = simple_tlv(0x87, t.reader_eph_x);
    std::copy(t3.begin(), t3.end(), std::back_inserter(tlv));
    auto t4 = simple_tlv(0x4C, t.transaction_id);
    std::copy(t4.begin(), t4.end(), std::back_inserter(tlv));
    auto t5 = simple_tlv(0x93, readerCtx);
    std::copy(t5.begin(), t5.end(), std::back_inserter(tlv));
    return tlv;
}

std::vector<uint8_t> HomeKeyStdAuth::buildVerificationInput()
{
    auto& t = session_.transcript();

    std::vector<uint8_t> tlv;
    tlv.reserve(t.reader_identifier.size() + t.endpoint_eph_x.size() +
                t.reader_eph_x.size() + t.transaction_id.size() + 15);

    auto t1 = simple_tlv(0x4D, t.reader_identifier);
    std::copy(t1.begin(), t1.end(), std::back_inserter(tlv));
    auto t2 = simple_tlv(0x86, t.endpoint_eph_x);
    std::copy(t2.begin(), t2.end(), std::back_inserter(tlv));
    auto t3 = simple_tlv(0x87, t.reader_eph_x);
    std::copy(t3.begin(), t3.end(), std::back_inserter(tlv));
    auto t4 = simple_tlv(0x4C, t.transaction_id);
    std::copy(t4.begin(), t4.end(), std::back_inserter(tlv));
    auto t5 = simple_tlv(0x93, deviceCtx);
    std::copy(t5.begin(), t5.end(), std::back_inserter(tlv));
    return tlv;
}

HomeKeyStdAuthResult HomeKeyStdAuth::attest()
{
    auto& t = session_.transcript();
    auto& store = session_.store();

    // --- Build AUTH1 APDU ---

    // Reader signs the signature input
    auto sigInput = buildAuth1SignatureInput();
    auto& reader_sk = store.reader_identity().private_key;
    auto sigPoint = CommonCryptoUtils::signSharedInfo(
        sigInput.data(), sigInput.size(), reader_sk.data(), reader_sk.size());

    auto sigTlv = simple_tlv(0x9E, sigPoint);
    std::vector<uint8_t> apdu{0x80, 0x81, 0x00, 0x00};
    apdu.push_back(static_cast<uint8_t>(sigTlv.size()));
    apdu.insert(apdu.end(), sigTlv.begin(), sigTlv.end());

    LOG(D, "%s", redactHex("Auth1 APDU", apdu).c_str());
    auto response = session_.apdu().transceive(apdu);
    LOG(D, "%s", redactHex("Auth1 Response", response.data).c_str());
    if(!response.ok()) LOG(D, "ERROR: %02x %02x", response.sw1, response.sw2);

    // --- ECDH + X963KDF (shared secret) ---

    uint8_t sharedKey[32]{};
    CommonCryptoUtils::get_shared_key(
        t.reader_eph_priv, t.endpoint_eph_pub, sharedKey, sizeof(sharedKey));
    LOG_HEX(D, "Shared Key", sharedKey);

    X963KDF kdf(MBEDTLS_MD_SHA256, 32, t.transaction_id.data(), 16);
    std::array<uint8_t,32> derivedKey{};
    kdf.derive(sharedKey, sizeof(sharedKey), derivedKey.data());
    LOG_HEX(D, "X963KDF Derived Key", derivedKey);

    // --- Key schedule: persistent + volatile ---

    HomeKeyKeySchedule schedule;
    HomeKeyKeySchedule::SessionInput input{
        store.reader_identity().public_key_x,
        t.reader_identifier,
        t.reader_eph_x,
        t.endpoint_eph_x,
        t.transaction_id,
        t.protocol_version,
        t.flags,
    };
    auto ks = schedule.derive_standard(input, derivedKey);
    auto& persistentKey = ks.persistent_key;
    auto& volatileKey = ks.volatile_key;

    LOG_HEX(D, "Persistent Key", persistentKey);
    LOG_HEX(D, "Volatile Key", volatileKey);

    // --- Decrypt AUTH1 response ---

    constexpr size_t minSecureResponseSize = 16 + 8; // ciphertext + RMAC
    if (!response.ok() || response.data.size() < minSecureResponseSize) {
        LOG(E, "STANDARD: Auth1 response too short or bad SW");
        return {};
    }

    auto scb = std::make_unique<ScbSecureChannel>(volatileKey);
    auto decrypted = scb->decrypt_response(
        response.data.data(), response.data.size());
    if (decrypted.empty()) {
        LOG(E, "STANDARD: SCB decrypt failed (RMAC mismatch)");
        return {};
    }

    LOG(D, "%s", redactHex("Decrypted", decrypted).c_str());

    // --- Parse decrypted TLV ---

    TLV8 tlv;
    tlv.parse(decrypted.data(), decrypted.size());
    auto sigItem = tlv.expect(0x9E);
    if (!sigItem) {
        LOG(E, "STANDARD: missing device signature (0x9E)");
        return {};
    }
    std::vector<uint8_t> signature = sigItem->value;

    // Find endpoint by device identifier (0x4E)
    auto idItem = tlv.expect(0x4E);
    if (!idItem || idItem->value.empty()) {
        LOG(E, "STANDARD: missing or empty device identifier (0x4E)");
        return {};
    }
    std::vector<uint8_t> deviceId = idItem->value;

    ddk::Issuer* foundIssuer = nullptr;
    ddk::Endpoint* foundEndpoint = nullptr;

    for (auto& issuer : store.issuers()) {
        for (auto& endpoint : issuer.endpoints) {
            if (endpoint.id.size() == deviceId.size() &&
                std::equal(endpoint.id.begin(), endpoint.id.end(),
                           deviceId.begin())) {
                LOG(D, "STD_AUTH: Found matching endpoint, ID: %s",
                    redactHex("", endpoint.id.data(), endpoint.id.size()).c_str());
                foundIssuer = &issuer;
                foundEndpoint = &endpoint;
                break;
            }
        }
        if (foundEndpoint) break;
    }

    if (!foundEndpoint) {
        LOG(W, "STANDARD: endpoint not found — will attempt attestation");
        HomeKeyStdAuthResult result;
        result.flow = ddk::kFlowNext;
        result.scb_context = std::move(scb);
        result.persistent_key = persistentKey;
        return result;
    }

    // --- Verify device signature ---

    auto verInput = buildVerificationInput();

    uint8_t hash[32]{};
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               verInput.data(), verInput.size(), hash);

    CommonCryptoUtils::EcpGroupGuard grp;
    CommonCryptoUtils::EcpPointGuard Q;
    CommonCryptoUtils::MpiGuard r, s;

    mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
    int ret = mbedtls_ecp_point_read_binary(grp, Q,
        foundEndpoint->public_key.data(), foundEndpoint->public_key.size());
    if (ret != 0) {
        LOG(E, "STANDARD: failed to read endpoint public key: %d", ret);
        return {};
    }

    mbedtls_mpi_read_binary(r, signature.data(), signature.size() / 2);
    mbedtls_mpi_read_binary(s, signature.data() + (signature.size() / 2),
                            signature.size() / 2);

    ret = mbedtls_ecdsa_verify(grp, hash, 32, Q, r, s);
    if (ret != 0) {
        LOG(W, "STANDARD: signature verification failed: %d", ret);
        HomeKeyStdAuthResult result;
        result.flow = ddk::kFlowNext;
        result.scb_context = std::move(scb);
        result.persistent_key = persistentKey;
        return result;
    }

    LOG(D, "STANDARD: signature verified");

    HomeKeyStdAuthResult result;
    result.issuer = foundIssuer;
    result.endpoint = foundEndpoint;
    result.scb_context = std::move(scb);
    result.persistent_key = persistentKey;
    result.flow = ddk::kFlowSTANDARD;
    return result;
}
