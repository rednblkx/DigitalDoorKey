#include "AliroSecureContext.h"
#include "DDKLogging.h"
#include <array>

constexpr const char* TAG = "AliroSecureContext";

AliroSecureContext::AliroSecureContext(std::array<uint8_t, 32> sk_reader, std::array<uint8_t, 32> sk_device)
  : exchange_channel_(sk_reader, sk_device) {};

ddk::ApduResponse AliroSecureContext::exchange(
    ddk::Session& session, ddk::span<const uint8_t> tlvs)
{
    auto encrypted = exchange_channel_.encrypt_reader_data(
        std::vector<uint8_t>(tlvs.begin(), tlvs.end()));
    if (encrypted.empty() && !tlvs.empty()) {
        LOG(E, "GCM encrypt failed");
        return {};
    }

    // Aliro EXCHANGE: CLA=0x80, INS=0xC9, P1=0x00, P2=0x00
    std::vector<uint8_t> apdu{0x80, 0xC9, 0x00, 0x00,
                              static_cast<uint8_t>(encrypted.size())};
    apdu.insert(apdu.end(), encrypted.begin(), encrypted.end());

    auto resp = session.apdu().transceive(apdu);
    if (!resp.ok() || resp.data.empty()) {
        return resp;
    }

    auto plaintext = exchange_channel_.decrypt_endpoint_data(resp.data);
    return {std::move(plaintext), resp.sw1, resp.sw2};
}
