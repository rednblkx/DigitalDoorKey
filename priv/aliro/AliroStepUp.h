#pragma once
#include "SignalingBitmask.h"
#include "ddk/session/Session.h"
#include <map>
#include <string>
#include <vector>

namespace ddk {
  class Issuer;
}

struct AliroStepUpResult {
    bool success = false;
    ddk::Issuer* issuer = nullptr;                 // matched by issuer_id
    std::vector<uint8_t> endpoint_public_key;      // 65B from MSO deviceKey
    std::vector<std::vector<uint8_t>> documents;   // full document CBOR blobs
    std::vector<uint8_t> access_document_cbor;     // first doc with docType "aliro-a"
};

class AliroSecureContext;

class AliroStepUp {
public:
    AliroStepUp(ddk::Session& session, AliroSecureContext& step_up_channel,
                size_t max_command_data_size = 255);

    // signaling_bitmap: from AUTH1 response tag 0x5E
    // scopes: elementIdentifier → intentToRetain (from SessionConfig)
    AliroStepUpResult run(ddk::aliro::SignalingBitmask signaling_bitmap,
                          const std::map<std::string, bool>& scopes);

private:
    ddk::Session& session_;
    AliroSecureContext& ctx_;
    size_t max_command_data_size_ = 255;

    void selectStepUpAid();
    std::vector<uint8_t> buildDeviceRequest(
        const std::vector<std::string>& doc_types,
        const std::map<std::string, bool>& scopes);
    AliroStepUpResult parseDeviceResponse(ddk::span<const uint8_t> cbor);
    bool extractDeviceKey(ddk::span<const uint8_t> payload,
                          std::vector<uint8_t>& x_out,
                          std::vector<uint8_t>& y_out);
};
