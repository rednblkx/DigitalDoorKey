#include "ddk/session/Session.h"
#include "CommonCryptoUtils.h"
#include "ddk/store/CredentialStore.h"
#include "ddk/store/ReaderIdentity.h"
#include "DDKLogging.h"
#include <chrono>

#if defined(CONFIG_IDF_CMAKE)
#include <esp_random.h>
#else
#include "sodium.h"
#endif

namespace ddk {


constexpr const char *TAG = "Session";

Session::Session(std::shared_ptr<ApduChannel> apdu,
                 CredentialStore& store,
                 SessionConfig config)
    : apdu_(std::move(apdu))
    , store_(store)
    , config_(std::move(config))
{
    auto& identity = store_.reader_identity();
    transcript_.reader_pk_x = ddk::span<const uint8_t>(
        identity.public_key_x.data(), identity.public_key_x.size());

    transcript_.reader_identifier.reserve(
        identity.group_identifier.size() + identity.sub_identifier.size());
    transcript_.reader_identifier.insert(
        transcript_.reader_identifier.end(),
        identity.group_identifier.begin(),
        identity.group_identifier.end());
    transcript_.reader_identifier.insert(
        transcript_.reader_identifier.end(),
        identity.sub_identifier.begin(),
        identity.sub_identifier.end());

    auto startTime = std::chrono::high_resolution_clock::now();;
    auto [priv, pub] = CommonCryptoUtils::generateEphemeralKey();
    transcript_.reader_eph_priv = priv;
    transcript_.reader_eph_pub  = pub;
    transcript_.reader_eph_x     = CommonCryptoUtils::get_x(transcript_.reader_eph_pub);

#if defined(CONFIG_IDF_CMAKE)
    esp_fill_random(transcript_.transaction_id.data(), 16);
#else
    randombytes(transcript_.transaction_id.data(), 16);
#endif
    LOG(I, "Session initialized in %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
}

}  // namespace ddk
