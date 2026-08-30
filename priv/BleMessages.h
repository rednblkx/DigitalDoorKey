#pragma once
#include "ddk/Span.h"
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

// Aliro BLE message layer. One or more Aliro messages ride in
// a single L2CAP SDU on the credit-based channel; framing is
//   1B Protocol Header | 1B Message ID | 2B Length (MSB first) | Payload
// with attribute payloads formatted as 1B id | 1B len | value.
namespace ddk::ble {

enum class ProtocolType : uint8_t {
    Ap = 0,           // AP_RQ / AP_RS — payload is a raw ISO 7816 APDU
    UwbRanging = 1,   // Ranging Session Setup M1–M4, suspend/resume
    Notification = 2,
    Supplementary = 3,
    ThirdPartyApp = 4,
};

struct Message {
    ProtocolType type = ProtocolType::Notification;
    uint8_t message_id = 0;
    std::vector<uint8_t> payload;

    std::vector<uint8_t> encode() const;
    // Decodes one message at cursor, advancing it. nullopt on malformed
    // framing (truncated header, zero-length payload).
    static std::optional<Message> decode(const uint8_t*& cursor, const uint8_t* end);
};

// AAD for BleSK-secured payloads: the 4 header bytes carrying the PLAIN
// payload length. The transmitted Length field covers ciphertext+tag,
// so the receiver rebuilds the AAD as Length − 16.
std::array<uint8_t,4> message_aad(ProtocolType type, uint8_t message_id,
                                  size_t plain_length);

namespace ap_id {
constexpr uint8_t kApRq = 0;
constexpr uint8_t kApRs = 1;
}

namespace notification_id {
constexpr uint8_t kEvent = 0;
constexpr uint8_t kRanging = 1;
constexpr uint8_t kReaderStatusChanged = 2;
constexpr uint8_t kReaderStatusApCompleted = 3;
constexpr uint8_t kRkeRequest = 4;
constexpr uint8_t kInitiateAccessProtocol = 5;
constexpr uint8_t kInitiateAccessProtocolRke = 6;
}

namespace event_attr {
constexpr uint8_t kBusy = 0;
constexpr uint8_t kGeneralError = 1;
constexpr uint8_t kReaderDescriptor = 2;
}
enum class GeneralError : uint8_t {
    Unknown = 0,
    ResourceUnavailable = 1,
    WrongParameters = 2,
    UrskUnavailable = 3,
};

namespace ranging_attr {
constexpr uint8_t kInitiateRangingSession = 0;
constexpr uint8_t kInitiateRangingSessionResume = 1;
constexpr uint8_t kInitiateRangingSessionSetupLater = 2;
constexpr uint8_t kInitiateRangingSessionResumeLater = 3;
constexpr uint8_t kSecureRangingOverUwbRadioFailed = 4;
constexpr uint8_t kRangingSessionSuspended = 5;
}

enum class OperationSource : uint8_t {
    Unspecified = 0,
    Manual = 1,
    Auto = 2,
    Schedule = 3,
    ThisDeviceBleUwb = 4,
    ThisDeviceNfc = 5,
    ThisDeviceBleOnly = 6,
    Matter = 7,
};

namespace rke_action {
constexpr uint8_t kSecure = 0;
constexpr uint8_t kUnsecure = 1;
}

namespace time_sync_attr {
constexpr uint8_t kDeviceEventCount = 0;
constexpr uint8_t kUwbDeviceTime = 1;
constexpr uint8_t kUwbDeviceTimeUncertainty = 2;
constexpr uint8_t kUwbClockSkewMeasurementAvailable = 3;
constexpr uint8_t kDeviceMaxPpm = 4;
constexpr uint8_t kSuccess = 5;
constexpr uint8_t kRetryDelay = 6;
}


struct Attribute {
    uint8_t id = 0;
    std::vector<uint8_t> value;
};

std::vector<uint8_t> encode_attributes(const std::vector<Attribute>& attrs);
std::optional<std::vector<Attribute>> parse_attributes(ddk::span<const uint8_t> payload);
const Attribute* find_attribute(const std::vector<Attribute>& attrs, uint8_t id);

std::vector<uint8_t> event_busy();
std::vector<uint8_t> event_general_error(GeneralError reason);
// Reader Information: bits[15:13] unsolicited mode,
// bits[7:0] reader status byte.
std::vector<uint8_t> reader_status_ap_completed(uint8_t status_byte,
                                                uint8_t unsolicited_mode);
// State: bits[15:8] operation source, bits[7:0] status byte.
std::vector<uint8_t> reader_status_changed(uint8_t status_byte, OperationSource source);
// Action: 1B, rke_action::kSecure / kUnsecure.
std::vector<uint8_t> rke_request(bool secure);
// Zero-length Ranging attribute.
std::vector<uint8_t> ranging_attribute(uint8_t id);

std::vector<uint8_t> pack_sdu(const std::vector<Message>& messages);
std::vector<Message> unpack_sdu(ddk::span<const uint8_t> sdu);

}  // namespace ddk::ble
