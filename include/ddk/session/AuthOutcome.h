#pragma once
#include <cstdint>
#include <ddk/Span.h>

namespace ddk {

class Issuer;
class Endpoint;

enum class FlowState : uint8_t {
    NotStarted,
    Selected,
    FastAttempted,
    FastHit,
    Auth1Attempted,
    Auth1Done,
    StepUpAttempted,
    Done,
    Failed,
};

enum class FailureReason : uint8_t {
    None,
    Auth0Reject,
    Auth0FastMiss,
    Auth1Reject,
    Auth1TagMismatch,
    Auth1MissingIdentity,
    AccessCredentialNotFound,
    AttestationInvalid,
    EnvelopeError,
    ControlFlowError,
    VersionMismatch,
    ChannelError,
};

struct AuthOutcome {
    FlowState     state = FlowState::Failed;
    FailureReason reason = FailureReason::None;
    Issuer*       issuer = nullptr;
    Endpoint*     endpoint = nullptr;
    span<const uint8_t> access_document_cbor;  // Aliro StepUp only

    explicit operator bool() const { return state == FlowState::Done; }
};

}  // namespace ddk
