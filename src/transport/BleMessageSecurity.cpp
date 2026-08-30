#include "BleMessageSecurity.h"
#include "DDKLogging.h"

namespace {
constexpr const char* TAG = "BleMsgSec";
constexpr uint32_t kMaxCounter = 0xFFFF;
constexpr size_t kGcmTagSize = 16;
}  // namespace

BleMessageSecurity::BleMessageSecurity(const std::array<uint8_t,32>& sk_reader,
                                       const std::array<uint8_t,32>& sk_device,
                                       bool device_role,
                                       uint32_t counter_reader,
                                       uint32_t counter_device)
    : channel_(sk_reader, sk_device, counter_reader, counter_device),
      device_role_(device_role) {}

std::optional<std::vector<uint8_t>> BleMessageSecurity::seal(const ddk::ble::Message& msg) {
    if (msg.type == ddk::ble::ProtocolType::Ap || !secured_)
        return msg.payload;  // clear (pre-AP-Completed window or AP layer)

    if (msg.payload.empty()) {
        LOG(E, "refusing to seal zero-length payload (malformed)");
        aborted_ = true;
        return std::nullopt;
    }
    auto aad = ddk::ble::message_aad(msg.type, msg.message_id, msg.payload.size());
    auto ct = device_role_
        ? channel_.encrypt_endpoint_data(msg.payload, aad)
        : channel_.encrypt_reader_data(msg.payload, aad);
    if (ct.empty()) {
        LOG(E, "BleSK seal failed");
        aborted_ = true;
        return std::nullopt;
    }
    uint32_t send_counter = device_role_ ? channel_.counter_endpoint()
                                         : channel_.counter_reader();
    if (send_counter > kMaxCounter) {
        LOG(E, "send message counter exhausted — aborting session");
        aborted_ = true;
    }
    return ct;
}

std::optional<std::vector<uint8_t>> BleMessageSecurity::unseal(const ddk::ble::Message& msg) {
    if (msg.type == ddk::ble::ProtocolType::Ap || !secured_)
        return msg.payload;

    if (msg.payload.size() < kGcmTagSize) {
        LOG(E, "secured payload shorter than the GCM tag");
        aborted_ = true;
        return std::nullopt;
    }
    size_t plain_len = msg.payload.size() - kGcmTagSize;
    auto aad = ddk::ble::message_aad(msg.type, msg.message_id, plain_len);
    auto pt = device_role_
        ? channel_.decrypt_reader_data(msg.payload, aad)
        : channel_.decrypt_endpoint_data(msg.payload, aad);
    if (pt.empty()) {
        LOG(E, "BleSK unseal failed (tag verification) — aborting session");
        aborted_ = true;
        return std::nullopt;
    }
    uint32_t recv_counter = device_role_ ? channel_.counter_reader()
                                         : channel_.counter_endpoint();
    if (recv_counter > kMaxCounter) {
        LOG(E, "receive message counter exhausted — aborting session");
        aborted_ = true;
    }
    return pt;
}
