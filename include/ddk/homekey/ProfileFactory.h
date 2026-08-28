#pragma once
#include "ddk/session/Profile.h"
#include <memory>

namespace ddk{

  class CredentialStore;

  namespace homekey {

  std::unique_ptr<ddk::Profile> make_profile();

  }
}  // namespace ddk::homekey
