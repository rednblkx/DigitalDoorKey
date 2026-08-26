#include "ddk/session/Session.h"
#include "ddk/store/CredentialStore.h"
#include "ddk/store/ReaderIdentity.h"
#include "DDKLogging.h"

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

    transcript_.flags = {0x01, 0x01};
    LOG(I, "Session initialized");
}

}  // namespace ddk
