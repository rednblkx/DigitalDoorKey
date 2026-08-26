#include "aliro/Profile.h"
#include "ddk/store/CredentialStore.h"
#include <memory>

namespace ddk::aliro {

std::unique_ptr<ddk::Profile> make_profile(CredentialStore& store)
{
    return std::make_unique<Profile>(store);
}

}  // namespace ddk::aliro
