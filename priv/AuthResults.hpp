#pragma once
#include <memory>
#include <array>
#include "DDKReaderData.h" 
#include "ScbSecureChannel.h"
#include "ddk/store/CredentialStore.h"
#include "ddk/store/Issuer.h"

/**
 * Result of the higher-level Context authentication.
 */
struct AuthContextResult {
    std::vector<uint8_t> issuer_id;
    std::vector<uint8_t> endpoint_id;
    KeyFlow flow = kFlowFailed;
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
    KeyFlow flow = kFlowFailed;
    explicit operator bool() const { return flow == kFlowFAST; }
};

struct HomeKeyStdAuthResult {
    ddk::Issuer* issuer = nullptr;
    ddk::Endpoint* endpoint = nullptr;
    std::unique_ptr<ScbSecureChannel> scb_context;
    std::array<uint8_t,32> persistent_key{};
    KeyFlow flow = kFlowFailed;
    explicit operator bool() const { return flow == kFlowSTANDARD && issuer && endpoint; }
};

struct AliroStdAuthResult {
    ddk::Issuer* issuer = nullptr;
    ddk::Endpoint* endpoint = nullptr;
    std::array<uint8_t,32> exchange_sk_reader{};
    std::array<uint8_t,32> exchange_sk_device{};
    std::array<uint8_t,32> persistent_key{};
    KeyFlow flow = kFlowFailed;
    explicit operator bool() const { return flow == kFlowSTANDARD && issuer && endpoint; }
};

struct HKAttestationResult {
    ddk::Issuer* issuer = nullptr;
    std::array<uint8_t,65> device_pub_key{};
    KeyFlow flow = kFlowFailed;
    explicit operator bool() const { return flow == kFlowATTESTATION; }
};
