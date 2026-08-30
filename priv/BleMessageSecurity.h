#pragma once
#include "BleMessages.h"
#include "GcmSecureChannel.h"
#include <array>
#include <cstdint>
#include <optional>

// BleSK message security: protocol types 1–4 are protected
// with BleSKReader/BleSKDevice — AES-256-GCM, IV = 8B direction ||
// 4B big-endian counter (both counters start at 1), AAD = 4B header with
// the plain payload length. AP (type 0) payloads never pass through here;
// they use the expedited/step-up channels inside the AP layer.
//
// Clear-text window: until Reader Status Access Protocol Completed is
// sent, non-AP messages pass through unencrypted (only reason-0 General
// Error and Busy are legal in clear). secured_ flips at AP Completed.
// A tag failure or a counter reaching 0xFFFF aborts the session — the
// owner must tear the BLE connection down.
class BleMessageSecurity {
public:
    // device_role=false (reader): seal encrypts with sk_reader, unseal
    // with sk_device. device_role=true (user device): mirrored. Counters
    // both start at 1.
    BleMessageSecurity(const std::array<uint8_t,32>& sk_reader,
                       const std::array<uint8_t,32>& sk_device,
                       bool device_role = false,
                       uint32_t counter_reader = 1,
                       uint32_t counter_device = 1);

    void set_secured(bool secured) { secured_ = secured; }
    bool secured() const { return secured_; }
    bool aborted() const { return aborted_; }

    // Encrypted payload (ct||tag) for transmission, or the clear payload
    // while not secured. nullopt = abort (also reflected in aborted()).
    std::optional<std::vector<uint8_t>> seal(const ddk::ble::Message& msg);
    // Plain payload; clear window passes non-AP payloads through.
    std::optional<std::vector<uint8_t>> unseal(const ddk::ble::Message& msg);

    uint32_t counter_reader() const { return channel_.counter_reader(); }
    uint32_t counter_device() const { return channel_.counter_endpoint(); }

private:
    GcmSecureChannel channel_;
    bool device_role_ = false;
    bool secured_ = false;
    bool aborted_ = false;
};
