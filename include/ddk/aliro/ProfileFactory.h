#pragma once
#include "ddk/session/Profile.h"
#include <memory>

namespace ddk::aliro {

std::unique_ptr<ddk::Profile> make_profile();

}  // namespace ddk::aliro
