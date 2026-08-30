#include "aliro/AliroFastAuth.h"
#include "aliro/AliroKeySchedule.h"
#include "CommonCryptoUtils.h"
#include "TLV8.hpp"
#include "ddk/store/CredentialStore.h"
#include "ddk/store/ReaderIdentity.h"

FastAuthResult AliroFastAuth::attest(const std::vector<uint8_t>& cryptogram)
{
    constexpr size_t kAliroCryptogramLength = 64;
    if (cryptogram.size() != kAliroCryptogramLength) {
        return {nullptr, nullptr, ddk::kFlowNext};
    }
    auto& t = session_.transcript();
    auto& store = session_.store();

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

    for (auto& issuer : store.issuers()) {
        for (auto& endpoint : issuer.endpoints) {
            if (endpoint.persistent_key.empty()) continue;
            auto result = schedule.derive_fast(
                input, endpoint.public_key_x, endpoint.persistent_key);
            std::array<uint8_t,32> sk{};
            std::copy_n(result.cryptogram_sk.data(), 32, sk.data());
            auto plaintext = CommonCryptoUtils::decryptAesGcm(
                cryptogram, sk, {0,0,0,0,0,0,0,0,0,0,0,0});
            if (!plaintext.empty()) {
                TLV8 tlv;
                tlv.parse(plaintext.data(), plaintext.size());
                if (tlv.expect(0x5E) && tlv.expect(0x91) && tlv.expect(0x92)) {
                    return {&issuer, &endpoint, ddk::kFlowFAST,
                            result.exchange_sk_reader, result.exchange_sk_device,
                            result.ble_sk, result.uwb_ranging_sk};
                }
            }
        }
    }
    return {nullptr, nullptr, ddk::kFlowNext};
}
