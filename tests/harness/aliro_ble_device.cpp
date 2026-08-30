#include "aliro_ble_device.hpp"

#include "aliro/AliroKeySchedule.h"
#include "BleMessages.h"

#include <utility>

namespace aliro_test {

AliroBleDevice::AliroBleDevice(std::shared_ptr<ddk::BleLink> link,
                               AliroTestEndpoint& endpoint,
                               std::vector<uint8_t> reader_supported_versions,
                               std::array<uint8_t,2> selected_version)
    : link_(std::move(link)),
      endpoint_(endpoint),
      endpoint_cb_(endpoint.callback()),
      reader_supported_versions_(std::move(reader_supported_versions)),
      selected_version_(selected_version)
{
    endpoint_.interface_kind = ddk::TransportKind::Ble;
}

void AliroBleDevice::start() {
    running_ = true;
    thread_ = std::thread([this] { run(); });
}

void AliroBleDevice::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
}

bool AliroBleDevice::send(const ddk::ble::Message& msg) {
    ddk::ble::Message out = msg;
    if (security_) {
        auto sealed = security_->seal(msg);
        if (!sealed) return false;
        out.payload = std::move(*sealed);
    }
    return link_->send_sdu(out.encode());
}

void AliroBleDevice::activate_security(const std::array<uint8_t, 32>& okm_slice) {
    auto keys = AliroKeySchedule::derive_ble_session_keys(
        ddk::span<const uint8_t>(okm_slice.data(), okm_slice.size()),
        reader_supported_versions_,
        ddk::span<const uint8_t>(selected_version_.data(), selected_version_.size()));
    security_.emplace(keys.sk_reader, keys.sk_device, /*device_role=*/true);
}

void AliroBleDevice::run() {
    if (initiate_armed_) {
        ddk::ble::Message m;
        m.type = ddk::ble::ProtocolType::Notification;
        m.message_id = initiate_rke_
            ? ddk::ble::notification_id::kInitiateAccessProtocolRke
            : ddk::ble::notification_id::kInitiateAccessProtocol;
        // Proprietary Information: the same 0xA5 TLV the NFC FCI carries.
        m.payload = ddk::ble::encode_attributes({{0, fci_proprietary()}});
        send(m);
    }

    std::vector<uint8_t> sdu;
    while (running_.load()) {
        if (!link_->recv_sdu(sdu, 50)) {
            if (!link_->connected()) break;
            continue;
        }
        auto messages = ddk::ble::unpack_sdu(sdu);
        for (auto& m : messages) {
            if (security_ && security_->secured() &&
                m.type == ddk::ble::ProtocolType::UwbRanging) {
                uwb_frames_seen.push_back(sdu);   // sealed, as on the wire
            }
            if (!handle_message(std::move(m))) {
                running_ = false;
                break;
            }
        }
    }
}

bool AliroBleDevice::handle_message(ddk::ble::Message msg) {
    using namespace ddk::ble;

    if (msg.type == ProtocolType::Ap) {
        if (msg.message_id != ap_id::kApRq) return false;   // reader sends AP_RQ only
        const auto& apdu = msg.payload;
        if (apdu.size() < 5) return false;

        apdus_seen.emplace_back(apdu[0], apdu[1]);
        if (silent_auth0_ && apdu[1] == 0x80) return true;  // reader must time out
        if (apdu[1] == 0x81) saw_auth1_ = true;

        std::vector<uint8_t> command(apdu.begin(), apdu.end());
        std::vector<uint8_t> response;
        if (!endpoint_cb_(command, response)) response = {0x6F, 0x00};

        // The first EXCHANGE without an AUTH1 marks the fast path — both
        // sides derive their BleSK channels from the same OKM slice.
        static constexpr std::array<uint8_t, 32> kZero{};
        if (!security_) {
            if (saw_auth1_ && endpoint_.std_ble_sk != kZero) {
                activate_security(endpoint_.std_ble_sk);
                ble_sk = endpoint_.std_ble_sk;
                ursk = endpoint_.std_ursk;
            } else if (!saw_auth1_ && endpoint_.fast_ble_sk != kZero) {
                activate_security(endpoint_.fast_ble_sk);
                ble_sk = endpoint_.fast_ble_sk;
                ursk = endpoint_.fast_ursk;
            }
        }
        if (apdu[1] == 0xC9) {
            exchange_payloads.push_back(endpoint_.completion_payload);
            if (endpoint_.completion_payload.size() >= 2 &&
                endpoint_.completion_payload[0] == 0x98 &&
                endpoint_.completion_payload[1] == 0x00)
                ++exchange_098_seen;
        }

        Message rs;
        rs.type = ProtocolType::Ap;
        rs.message_id = ap_id::kApRs;
        rs.payload = std::move(response);
        return send(rs);
    }

    if (msg.type == ProtocolType::Notification &&
        msg.message_id == notification_id::kReaderStatusApCompleted) {
        // First BleSK-encrypted message — flip the clear window before
        // unsealing.
        if (security_) security_->set_secured(true);
        auto plain = security_ ? security_->unseal(msg)
                               : std::optional<std::vector<uint8_t>>(msg.payload);
        if (!plain) return false;
        ap_completed_seen = true;
        ap_completed_payload = *plain;
        if (time_sync_armed_) send_time_sync();
        if (ranging_initiation_armed_) {
            Message init;
            init.type = ProtocolType::Notification;
            init.message_id = notification_id::kRanging;
            init.payload = ranging_attribute(ranging_attr::kInitiateRangingSession);
            if (!send(init)) return false;
        }
        if (rke_armed_) {
            Message rke;
            rke.type = ProtocolType::Notification;
            rke.message_id = notification_id::kRkeRequest;
            rke.payload = rke_request(rke_secure_);
            if (!send(rke)) return false;
        }
        return true;
    }

    if (msg.type == ProtocolType::Notification &&
        msg.message_id == notification_id::kReaderStatusChanged) {
        auto plain = security_ ? security_->unseal(msg)
                               : std::optional<std::vector<uint8_t>>(msg.payload);
        if (!plain) return false;
        reader_status_payloads.push_back(std::move(*plain));
        return true;
    }

    if (msg.type == ProtocolType::Notification &&
        msg.message_id == notification_id::kEvent) {
        auto plain = security_ ? security_->unseal(msg)
                               : std::optional<std::vector<uint8_t>>(msg.payload);
        if (!plain) return false;
        auto attrs = parse_attributes(*plain);
        if (attrs) {
            if (auto* err = find_attribute(*attrs, event_attr::kGeneralError);
                err && !err->value.empty())
                general_error_reasons.push_back(err->value[0]);
        }
        return true;
    }

    return true;   // Ranging/Supplementary/UWB — tolerated, phase 2
}

void AliroBleDevice::send_time_sync() {
    ddk::ble::Message m;
    m.type = ddk::ble::ProtocolType::Supplementary;
    m.message_id = 0;   // Time Sync
    m.payload = ddk::ble::encode_attributes({
        {ddk::ble::time_sync_attr::kDeviceEventCount,
         std::vector<uint8_t>(8, 0x01)},
        {ddk::ble::time_sync_attr::kUwbDeviceTime,
         {0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78}},
        {ddk::ble::time_sync_attr::kUwbDeviceTimeUncertainty, {0x10}},
        {ddk::ble::time_sync_attr::kUwbClockSkewMeasurementAvailable, {0x00}},
        {ddk::ble::time_sync_attr::kDeviceMaxPpm, {0x00, 0x14}},
        {ddk::ble::time_sync_attr::kSuccess, {0x01}},
        {ddk::ble::time_sync_attr::kRetryDelay, {0x00, 0x00}},
    });
    send(m);
}

}  // namespace aliro_test
