#pragma once
#include <cstdint>
namespace ddk::aliro {
// Reader status. Encoded as (s1 << 8) | s2.
enum class ReaderStatus : uint16_t {
    // Failure codes (s1 = 0x00)
    PublicKeyNotFound   = 0x0001,
    PublicKeyExpired    = 0x0002,
    PublicKeyNotTrusted = 0x0003,
    InvalidSignature    = 0x0004,
    InvalidDataFormat   = 0x0006,
    InvalidDataContent  = 0x0007,
    StatusWordError     = 0x0020,
    NoKeySlot           = 0x0021,
    NoPublicKey         = 0x0022,
    NoSignaturePresent  = 0x0023,
    InvalidAccessRights = 0x0025,
    HardwareIssue       = 0x0026,
    // Reader state codes (s1 = 0x01)
    StateSecure         = 0x0100,   // locked, armed, closed
    StateUnsecure       = 0x0101,   // unlocked, disarmed, opened
    StateObstructed     = 0x0102,
    EnteringSecure      = 0x0180,
    EnteringUnsecure    = 0x0181,
    StateUnknown        = 0x0182,
};
}
