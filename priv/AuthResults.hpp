#pragma once
#include <memory>
#include <array>
#include <optional>
#include "GcmSecureChannel.h"
#include "ScbSecureChannel.h"
#include "ddk/store/Issuer.h"

/**
 * Result of the higher-level Context authentication.
 */
struct AuthContextResult {
    std::vector<uint8_t> issuer_id;
    std::vector<uint8_t> endpoint_id;
    ddk::KeyFlow flow = ddk::kFlowFailed;
};

/**
 * Result of verifying the attestation response.
 */
struct HKAttestationVerificationResult {
    ddk::Issuer* issuer = nullptr;
    std::array<uint8_t, 65> device_pub_key{};

    explicit operator bool() const { return issuer != nullptr; }
};

struct FastAuthResult {
    ddk::Issuer* issuer = nullptr;
    ddk::Endpoint* endpoint = nullptr;
    ddk::KeyFlow flow = ddk::kFlowFailed;
    std::array<uint8_t,32> exchange_sk_reader{};
    std::array<uint8_t,32> exchange_sk_device{};
    std::array<uint8_t,32> ble_sk{};
    std::array<uint8_t,32> uwb_ranging_sk{};
    explicit operator bool() const { return flow == ddk::kFlowFAST; }
};

struct HomeKeyStdAuthResult {
    ddk::Issuer* issuer = nullptr;
    ddk::Endpoint* endpoint = nullptr;
    std::unique_ptr<ScbSecureChannel> scb_context;
    std::array<uint8_t,32> persistent_key{};
    ddk::KeyFlow flow = ddk::kFlowFailed;
    explicit operator bool() const { return flow == ddk::kFlowSTANDARD && issuer && endpoint; }
};

struct AliroStdAuthResult {
    ddk::Issuer* issuer = nullptr;
    ddk::Endpoint* endpoint = nullptr;
    std::unique_ptr<GcmSecureChannel> gcm_context;
    std::array<uint8_t,32> step_up_sk_reader{};
    std::array<uint8_t,32> step_up_sk_device{};
    std::array<uint8_t,32> persistent_key{};
    std::array<uint8_t,32> derived_key{};
    std::array<uint8_t,32> ble_sk{};
    std::array<uint8_t,32> uwb_ranging_sk{};
    std::vector<uint8_t> key_slot;
    std::optional<std::array<uint8_t,2>> signaling_bitmap{};
    std::vector<uint8_t> credential_signed_timestamp;
    std::vector<uint8_t> revocation_signed_timestamp;
    ddk::KeyFlow flow = ddk::kFlowFailed;
    explicit operator bool() const { return flow == ddk::kFlowSTANDARD && issuer && endpoint; }
};

struct HKAttestationResult {
    ddk::Issuer* issuer = nullptr;
    std::array<uint8_t,65> device_pub_key{};
    ddk::KeyFlow flow = ddk::kFlowFailed;
    explicit operator bool() const { return flow == ddk::kFlowATTESTATION; }
};
