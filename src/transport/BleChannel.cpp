#include "BleChannel.h"
#include "ApduChaining.h"
#include "BleMessages.h"
#include "BleTransport.h"
#include "DDKLogging.h"
#include <chrono>

namespace {
constexpr const char* TAG = "BleChannel";
}  // namespace

BleChannel::BleChannel(AliroBleTransport& transport, uint32_t response_timeout_ms)
    : transport_(transport), response_timeout_ms_(response_timeout_ms) {}

ddk::TransportKind BleChannel::kind() const { return ddk::TransportKind::Ble; }

size_t BleChannel::max_command_payload() const {
    // Room left for an APDU inside one SDU after the 4-byte message header.
    size_t sdu = transport_.max_sdu_size();
    return sdu > 4 ? sdu - 4 : 0;
}

ddk::ApduResponse BleChannel::transceive(ddk::span<const uint8_t> capdu) {
    using clock = std::chrono::steady_clock;

    if (capdu.empty()) return {{}, 0x6F, 0x00};

    ddk::ble::Message rq;
    rq.type = ddk::ble::ProtocolType::Ap;
    rq.message_id = ddk::ble::ap_id::kApRq;
    rq.payload.assign(capdu.begin(), capdu.end());
    if (!transport_.send(rq))
        return {{}, 0x6F, 0x00};

    auto deadline = clock::now() + std::chrono::milliseconds(response_timeout_ms_);
    for (;;) {
        long remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - clock::now()).count();
        if (remaining <= 0) {
            // responseTimeout expiry — the transmitter initiates BLE
            // teardown.
            LOG(W, "responseTimeout expired — initiating teardown");
            transport_.close_link();
            return {{}, 0x6F, 0x00};
        }

        auto msg = transport_.receive(static_cast<uint32_t>(remaining));
        if (!msg) {
            if (transport_.link_down() || transport_.security_aborted())
                transport_.close_link();
            return {{}, 0x6F, 0x00};
        }

        if (msg->type == ddk::ble::ProtocolType::Ap) {
            if (msg->message_id != ddk::ble::ap_id::kApRs) {
                LOG(E, "unexpected AP_RQ from the user device");
                return {{}, 0x6F, 0x00};
            }
            if (msg->payload.size() < 2) {
                LOG(E, "AP_RS payload missing status word");
                return {{}, 0x6F, 0x00};
            }
            ddk::ApduResponse resp;
            resp.data.assign(msg->payload.begin(), msg->payload.end() - 2);
            resp.sw1 = msg->payload[msg->payload.size() - 2];
            resp.sw2 = msg->payload[msg->payload.size() - 1];
            return resp;
        }

        // Non-AP message during the AP exchange: Busy resets the
        // responseTimeout, General Error forces teardown, everything
        // else is parked for the flow.
        if (msg->type == ddk::ble::ProtocolType::Notification &&
            msg->message_id == ddk::ble::notification_id::kEvent) {
            auto attrs = ddk::ble::parse_attributes(msg->payload);
            if (attrs && ddk::ble::find_attribute(*attrs, ddk::ble::event_attr::kBusy)) {
                LOG(D, "Event Busy — responseTimeout reset");
                deadline = clock::now() + std::chrono::milliseconds(response_timeout_ms_);
                continue;
            }
            if (attrs && ddk::ble::find_attribute(*attrs, ddk::ble::event_attr::kGeneralError)) {
                LOG(W, "Event General Error from device — initiating teardown");
                transport_.close_link();
                return {{}, 0x6F, 0x00};
            }
        }
        transport_.deferred().push_back(std::move(*msg));
    }
}

ddk::ApduResponse BleChannel::transceive_full(
    const ddk::ApduCommand& command, bool skip_response_chaining,
    size_t max_command_chunk) {
    return ddk::detail::transceive_with_chaining(*this, command,
                                                 skip_response_chaining,
                                                 max_command_chunk);
}
