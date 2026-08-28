#include "AliroStdAuth.h"
#include "AliroKeySchedule.h"
#include "ddk/store/ReaderIdentity.h"
#include "CommonCryptoUtils.h"
#include "GcmSecureChannel.h"
#include "x963kdf.h"
#include "simple_tlv.hpp"
#include "TLV8.hpp"
#include "DDKLogging.h"
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/md.h>
#include <mbedtls/ecp.h>
#include <cstring>
#include <vector>

constexpr const char* TAG = "AliroStdAuth";

std::vector<uint8_t> AliroStdAuth::buildAuth1SignatureInput()
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

std::vector<uint8_t> AliroStdAuth::buildVerificationInput()
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

AliroStdAuthResult AliroStdAuth::attest()
{
    auto& t = session_.transcript();
    auto& store = session_.store();

    // --- Build AUTH1 APDU (Aliro: 0x41 0x01 0x01 prepended) ---

    auto sigInput = buildAuth1SignatureInput();
    auto& reader_sk = store.reader_identity().private_key;
    auto sigPoint = CommonCryptoUtils::signSharedInfo(
        sigInput.data(), sigInput.size(), reader_sk.data(), reader_sk.size());

    auto sigTlv = simple_tlv(0x9E, sigPoint);

    // Aliro AUTH1: CLA=0x80 INS=0x81 P1=0x00 P2=0x00
    // Data: 0x41 0x01 0x01 (REQUEST_PUBLIC_KEY) + signature TLV
    std::vector<uint8_t> apdu{0x80, 0x81, 0x00, 0x00};
    apdu.push_back(static_cast<uint8_t>(sigTlv.size() + 3)); // +3 for 41 01 01
    apdu.push_back(0x41);
    apdu.push_back(0x01);
    apdu.push_back(0x01); // REQUEST_PUBLIC_KEY
    apdu.insert(apdu.end(), sigTlv.begin(), sigTlv.end());

    LOG(D, "%s", redactHex("Auth1 APDU", apdu).c_str());
    auto response = session_.apdu().transceive(apdu);
    LOG(D, "%s", redactHex("Auth1 Response", response.data).c_str());

    // --- ECDH + X963KDF ---

    uint8_t sharedKey[32]{};
    CommonCryptoUtils::get_shared_key(
        t.reader_eph_priv, t.endpoint_eph_pub, sharedKey, sizeof(sharedKey));
    LOG_HEX(D, "Shared Key", sharedKey);

    X963KDF kdf(MBEDTLS_MD_SHA256, 32, t.transaction_id.data(), 16);
    std::array<uint8_t,32> derivedKey{};
    kdf.derive(sharedKey, sizeof(sharedKey), derivedKey.data());
    LOG_HEX(D, "X963KDF Derived Key", derivedKey);

    // --- Key schedule: volatile only (persistent after signature verify) ---

    AliroKeySchedule schedule;
    AliroKeySchedule::SessionInput input{
        store.reader_identity().public_key_x,
        t.reader_identifier,
        t.reader_eph_x,
        t.endpoint_eph_x,
        t.transaction_id,
        t.protocol_version,
        t.flags,
        t.fci_proprietary,
        t.interface,
        t.auth0_info_suffix,
    };

    auto vol = schedule.derive_volatile(input, derivedKey);
    std::array<uint8_t,32> skReader = vol.exchange_sk_reader;
    std::array<uint8_t,32> skDevice = vol.exchange_sk_device;

    LOG(D, "Exchange SK Reader - %s",
        redactHex("", skReader.data(), 32).c_str());
    LOG(D, "Exchange SK Device - %s",
        redactHex("", skDevice.data(), 32).c_str());

    AliroStdAuthResult result;
    result.step_up_sk_reader = vol.step_up_sk_reader;
    result.step_up_sk_device = vol.step_up_sk_device;
    result.derived_key = derivedKey;

    // --- Decrypt AUTH1 response via GCM ---

    constexpr size_t minSecureResponseSize = 16; // minimum: GCM tag
    if (!response.ok() || response.data.size() < minSecureResponseSize) {
        LOG(E, "STANDARD: Auth1 response too short or bad SW");
        return result;
    }

    auto gcm = std::make_unique<GcmSecureChannel>(skReader, skDevice);
    auto decrypted = gcm->decrypt_endpoint_data(response.data);
    if (decrypted.empty()) {
        LOG(E, "STANDARD: GCM decrypt failed (tag mismatch)");
        return result;
    }

    LOG(D, "%s", redactHex("Decrypted", decrypted).c_str());

    result.gcm_context = std::move(gcm);

    // --- Parse decrypted TLV ---

    TLV8 tlv;
    tlv.parse(decrypted.data(), decrypted.size());

    auto sigItem = tlv.expect(0x9E);
    if (!sigItem) {
        LOG(E, "STANDARD: missing device signature (0x9E)");
        return result;
    }
    std::vector<uint8_t> signature = sigItem->value;
    if (signature.size() != 64) {
        LOG(E, "STANDARD: invalid signature length: %zu", signature.size());
        return result;
    }

    if (auto bm = tlv.expect(0x5E); bm && bm->value.size() == 2) {
        result.signaling_bitmap = std::array<uint8_t,2>{bm->value[0], bm->value[1]};
    }
    if (auto ks = tlv.expect(0x4E); ks && ks->value.size() == 8) {
        result.key_slot = ks->value;
    }
    if (auto ts = tlv.expect(0x91); ts && ts->value.size() == 20) {
        result.credential_signed_timestamp = ts->value;
    }
    if (auto ts = tlv.expect(0x92); ts && ts->value.size() == 20) {
        result.revocation_signed_timestamp = ts->value;
    }

    // Aliro: find endpoint by public key (0x5A)
    ddk::Issuer* foundIssuer = nullptr;
    ddk::Endpoint* foundEndpoint = nullptr;

    auto pkItem = tlv.expect(0x5A);
    if (pkItem && !pkItem->value.empty()) {
        std::vector<uint8_t> devicePk = pkItem->value;
        if (devicePk.size() == 64) {
            devicePk.insert(devicePk.begin(), 0x04); // add uncompressed prefix
        }

        for (auto& issuer : store.issuers()) {
            for (auto& endpoint : issuer.endpoints) {
                if (devicePk.size() >= endpoint.public_key.size() &&
                    std::equal(endpoint.public_key.begin(),
                               endpoint.public_key.end(),
                               devicePk.begin())) {
                    foundIssuer = &issuer;
                    foundEndpoint = &endpoint;
                    LOG(D, "Found matching endpoint by public key");
                    break;
                }
            }
            if (foundEndpoint) break;
        }
    }

    // Also check key_slot (0x4E) if present
    if (!foundEndpoint) {
        auto slotItem = tlv.expect(0x4E);
        if (slotItem && slotItem->value.size() == 8) {
            for (auto& issuer : store.issuers()) {
                for (auto& endpoint : issuer.endpoints) {
                    auto hash = CommonCryptoUtils::hash_identifier_sha1(endpoint.public_key);
                    if (hash.size() >= 8 &&
                        std::equal(slotItem->value.begin(), slotItem->value.end(),
                                  hash.begin())) {
                        foundIssuer = &issuer;
                        foundEndpoint = &endpoint;
                        break;
                    }
                }
                if (foundEndpoint) break;
            }
        }
    }

    if (!foundEndpoint) {
        LOG(W, "STANDARD: endpoint not found");
        result.flow = kFlowFailed;
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

    mbedtls_mpi_read_binary(r, signature.data(), 32);
    mbedtls_mpi_read_binary(s, signature.data() + 32, 32);

    ret = mbedtls_ecdsa_verify(grp, hash, 32, Q, r, s);
    if (ret != 0) {
        LOG(W, "STANDARD: signature verification failed: %d", ret);
        result.flow = kFlowFailed;
        return result;
    }

    LOG(D, "STANDARD: signature verified");

    // --- Derive persistent key (Aliro: after signature verify, uses ep_pk_x) ---

    auto persistentKey = schedule.derive_persistent(
        input, derivedKey, foundEndpoint->public_key_x);

    LOG_HEX(D, "Persistent Key", persistentKey);

    result.issuer = foundIssuer;
    result.endpoint = foundEndpoint;
    result.persistent_key = persistentKey;
    result.flow = kFlowSTANDARD;
    return result;
}
