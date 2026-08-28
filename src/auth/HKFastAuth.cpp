#include "homekey/HKFastAuth.h"
#include "homekey/HomeKeyKeySchedule.h"
#include "CommonCryptoUtils.h"
#include "DDKLogging.h"
#include "ddk/store/CredentialStore.h"
#include "ddk/store/ReaderIdentity.h"

constexpr const char* TAG = "HKFastAuth";

FastAuthResult HomeKeyFastAuth::attest(const std::vector<uint8_t>& cryptogram)
{
    auto& t = session_.transcript();
    auto& store = session_.store();

    if (cryptogram.size() != 16) {
        LOG(W, "Invalid HomeKey cryptogram length: %zu", cryptogram.size());
        return {nullptr, nullptr, ddk::kFlowNext};
    }

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

    for (auto& issuer : store.issuers()) {
        for (auto& endpoint : issuer.endpoints) {
            if (endpoint.persistent_key.empty()) continue;
            auto okm = schedule.derive_fast_material(
                input, endpoint.public_key_x, endpoint.persistent_key);
            if (CommonCryptoUtils::constant_time_compare(
                    okm.data(), cryptogram.data(), 16)) {
                return {&issuer, &endpoint, ddk::kFlowFAST};
            }
        }
    }
    return {nullptr, nullptr, ddk::kFlowNext};
}
