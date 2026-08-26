#pragma once
#include "ddk/session/Profile.h"
#include "ddk/store/CredentialStore.h"
#include <memory>

namespace ddk::aliro {

std::unique_ptr<ddk::Profile> make_profile(CredentialStore& store);

}  // namespace ddk::aliro
