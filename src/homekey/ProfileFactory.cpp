#include "homekey/Profile.h"
#include <memory>

namespace ddk::homekey {

std::unique_ptr<ddk::Profile> make_profile()
{
    return std::make_unique<Profile>();
}

}  // namespace ddk::homekey
