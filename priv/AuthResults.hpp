#pragma once
#include <memory>
#include <array>
#include "DDKReaderData.h" 

// Forward declarations of existing types
struct hkIssuer_t;
struct hkEndpoint_t;
class DigitalKeySecureContext;

/**
 * Result of the Attestation (Initial Pairing/Handshake) flow.
 */
struct AttestationResult {
    hkIssuer_t* issuer = nullptr;
    std::array<uint8_t,65> device_pub_key;
    KeyFlow flow = kFlowFailed;

    explicit operator bool() const { return issuer != nullptr; }
};

/**
 * Result of the Standard Authentication (Fast/Normal) flow.
 */
struct StandardAuthResult {
    hkIssuer_t* issuer = nullptr;
    hkEndpoint_t* endpoint = nullptr;
    std::unique_ptr<DigitalKeySecureContext> secure_context;
    std::array<uint8_t, 32> shared_secret;
    KeyFlow flow;

    explicit operator bool() const { return flow != 0; /* Replace with kFlowFailed equivalent */ }
};

/**
 * Result of the Fast Authentication flow.
 */
struct FastAuthResult {
    hkIssuer_t* issuer = nullptr;
    hkEndpoint_t* endpoint = nullptr;
    KeyFlow flow = kFlowFailed;

    explicit operator bool() const { return flow == kFlowFAST; }
};
