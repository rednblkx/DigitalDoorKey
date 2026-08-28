#include "aliro/Profile.h"
#include <memory>

namespace ddk::aliro {

std::unique_ptr<ddk::Profile> make_profile()
{
    return std::make_unique<Profile>();
}

}  // namespace ddk::aliro
