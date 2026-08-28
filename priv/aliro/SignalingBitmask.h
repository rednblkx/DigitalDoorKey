#pragma once
#include <cstdint>

namespace ddk::aliro {

enum class SignalingBitmask : uint16_t {
    AccessDocumentRetrievable     = 1 << 0,
    RevocationDocumentRetrievable = 1 << 1,
    StepUpSelectRequired          = 1 << 2,   // NFC only
    MailboxDataPresent            = 1 << 3,
    MailboxReadable               = 1 << 4,
    MailboxWriteable              = 1 << 5,
    NotifyIssuerBackendSupported  = 1 << 6,
    NotifyApplicationSupported    = 1 << 7,
    UpdateDocExpeditedSupported   = 1 << 9,
    MailboxInStepUp               = 1 << 10,
    NotifyInStepUp                = 1 << 11,
    UpdateDocInStepUp             = 1 << 12,
};

inline SignalingBitmask operator|(SignalingBitmask a, SignalingBitmask b) {
    return static_cast<SignalingBitmask>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
}
inline SignalingBitmask operator&(SignalingBitmask a, SignalingBitmask b) {
    return static_cast<SignalingBitmask>(static_cast<uint16_t>(a) & static_cast<uint16_t>(b));
}
inline SignalingBitmask operator^(SignalingBitmask a, SignalingBitmask b) {
    return static_cast<SignalingBitmask>(static_cast<uint16_t>(a) ^ static_cast<uint16_t>(b));
}
inline SignalingBitmask operator~(SignalingBitmask a) {
    return static_cast<SignalingBitmask>(~static_cast<uint16_t>(a));
}
inline SignalingBitmask& operator|=(SignalingBitmask& a, SignalingBitmask b) { return a = a | b; }
inline SignalingBitmask& operator&=(SignalingBitmask& a, SignalingBitmask b) { return a = a & b; }
// All bits of `bit` are set in `value`.
inline bool has(SignalingBitmask value, SignalingBitmask bit) {
    return (value & bit) == bit;
}

}  // namespace ddk::aliro
