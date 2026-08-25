#pragma once
#include <memory>
#include <array>
#include "DDKReaderData.h" 
#include "ScbSecureChannel.h"
#include "ddk/store/CredentialStore.h"

/**
 * Result of the Attestation (Initial Pairing/Handshake) flow.
 */
struct AttestationResult {
    ddk::Issuer* issuer = nullptr;
    std::array<uint8_t,65> device_pub_key{};
    KeyFlow flow = kFlowFailed;

    explicit operator bool() const { return issuer != nullptr && flow == kFlowATTESTATION; }
};

/**
 * Result of verifying the attestation response.
 */
struct AttestationVerificationResult {
    ddk::Issuer* issuer = nullptr;
    std::array<uint8_t, 65> device_pub_key{};

    explicit operator bool() const { return issuer != nullptr; }
};

/**
 * Result of the Standard Authentication (Fast/Normal) flow.
 */
struct StandardAuthResult {
    ddk::Issuer* issuer = nullptr;
    ddk::Endpoint* endpoint = nullptr;
    std::unique_ptr<ScbSecureChannel> scb_context;
    std::array<uint8_t, 32> shared_secret;
    KeyFlow flow = kFlowFailed;

    explicit operator bool() const {
        return flow == kFlowSTANDARD && issuer != nullptr && endpoint != nullptr;
    }
};

/**
 * Result of the Fast Authentication flow.
 */
struct FastAuthResult {
    ddk::Issuer* issuer = nullptr;
    ddk::Endpoint* endpoint = nullptr;
    KeyFlow flow = kFlowFailed;

    explicit operator bool() const { return flow == kFlowFAST; }
};
