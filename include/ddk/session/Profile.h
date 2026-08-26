#pragma once
#include "ddk/session/AuthOutcome.h"
#include "ddk/session/Session.h"

namespace ddk {

class Profile {
public:
  virtual ~Profile() = default;

  virtual FailureReason
  validate_select(Session &session,
                  std::span<const uint8_t> select_response) = 0;

  virtual FlowState step(Session &session, FlowState current) = 0;

  virtual AuthOutcome finalize(Session &session) = 0;

  virtual ApduResponse control_flow(Session &session, uint8_t s1,
                                    uint8_t s2) = 0;
};

} // namespace ddk
