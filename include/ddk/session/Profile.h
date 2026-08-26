#pragma once
#include "ddk/session/AuthOutcome.h"
#include "ddk/session/Session.h"

namespace ddk {

class Profile {
public:
  virtual ~Profile() = default;

  // Firmware did SELECT, passes FCI. Library validates version,
  // extracts max_command_data_size, stashes FCI into transcript.
  virtual FailureReason
  validate_select(Session &session,
                  std::span<const uint8_t> select_response) = 0;

  // Drive one state transition. Returns new state.
  // Firmware's main loop calls until Done or Failed.
  virtual FlowState step(Session &session, FlowState current) = 0;

  // Extract final result.
  virtual AuthOutcome finalize(Session &session) = 0;

  // Post-auth operations (after Done, if secure context exists)
  virtual ApduResponse exchange(Session &session,
                                std::span<const uint8_t> tlvs) = 0;
  virtual ApduResponse control_flow(Session &session, uint8_t s1,
                                    uint8_t s2) = 0;
};

} // namespace ddk
