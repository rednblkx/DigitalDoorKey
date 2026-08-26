#include "HKSecureContext.h"
#include "DDKLogging.h"

constexpr const char* TAG = "HKSecureContext";

HKSecureContext::HKSecureContext(std::unique_ptr<ScbSecureChannel> scb)
    : scb_(std::move(scb)) {}

ddk::ApduResponse HKSecureContext::exchange(
    ddk::Session& session, ddk::span<const uint8_t> tlvs)
{
    auto [encrypted, rmac] = scb_->encrypt_command(tlvs);

    if (encrypted.empty() && !tlvs.empty()) {
        LOG(E, "SCB encrypt failed");
        return {};
    }

    // EXCHANGE APDU: CLA=0x84, INS=0xC9, P1=0x00, P2=0x00
    std::vector<uint8_t> apdu{0x84, 0xC9, 0x00, 0x00,
                              static_cast<uint8_t>(encrypted.size())};
    apdu.insert(apdu.end(), encrypted.begin(), encrypted.end());

    auto resp = session.apdu().transceive(apdu);
    if (!resp.ok() || resp.data.empty()) {
        return resp;
    }
    if(resp.data.size() >= 24){
      auto plaintext = scb_->decrypt_response(resp.data.data(), resp.data.size());
      return {std::move(plaintext), resp.sw1, resp.sw2};
    }
    return resp;
}
