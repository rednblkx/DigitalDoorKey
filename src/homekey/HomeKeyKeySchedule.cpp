#include "homekey/HomeKeyKeySchedule.h"
#include "DDKLogging.h"
#include "ddk/transport/ApduChannel.h"
#include <cstdint>
#include <cstring>
#include <mbedtls/hkdf.h>

namespace {
constexpr const char* kVolatileFast = "VolatileFast";
constexpr const char* kVolatile     = "Volatile";
constexpr const char* kPersistent   = "Persistent";
constexpr std::array<uint8_t,6> kSupportedVersions = {0x5C, 0x04, 0x02, 0x00, 0x01, 0x00};
constexpr const char* TAG = "HomeKeyKeySchedule";

std::vector<uint8_t> build_fast_salt(
    const HomeKeyKeySchedule::SessionInput& input,
    ddk::span<const uint8_t> endpoint_pk_x)
{
    std::vector<uint8_t> salt;
    salt.reserve(input.reader_pk_x.size() + strlen(kVolatileFast) +
                 input.reader_identifier.size() + endpoint_pk_x.size() +
                 1 + kSupportedVersions.size() + 4 +
                 input.reader_eph_x.size() + input.transaction_id.size() +
                 2 + input.endpoint_eph_x.size());

    salt.insert(salt.end(), input.reader_pk_x.begin(), input.reader_pk_x.end());
    salt.insert(salt.end(), (const uint8_t*)kVolatileFast,
                (const uint8_t*)kVolatileFast + strlen(kVolatileFast));
    salt.insert(salt.end(), input.reader_identifier.begin(), input.reader_identifier.end());
    salt.insert(salt.end(), endpoint_pk_x.begin(), endpoint_pk_x.end());
    salt.push_back((uint8_t)ddk::TransportKind::Nfc);
    salt.insert(salt.end(), kSupportedVersions.begin(), kSupportedVersions.end());
    salt.push_back(0x5C);
    salt.push_back(input.version.size());
    salt.insert(salt.end(), input.version.begin(), input.version.end());
    salt.insert(salt.end(), input.reader_eph_x.begin(), input.reader_eph_x.end());
    salt.insert(salt.end(), input.transaction_id.begin(), input.transaction_id.end());
    salt.push_back(input.flags[0]);
    salt.push_back(input.flags[1]);
    salt.insert(salt.end(), input.endpoint_eph_x.begin(), input.endpoint_eph_x.end());
    return salt;
}

std::vector<uint8_t> build_standard_salt(
    const HomeKeyKeySchedule::SessionInput& input,
    std::string_view context)
{
    std::vector<uint8_t> salt;
    salt.reserve(input.reader_eph_x.size() + input.endpoint_eph_x.size() +
                 input.transaction_id.size() + 1 + 2 + context.size() +
                 2 + input.version.size() + kSupportedVersions.size());

    salt.insert(salt.end(), input.reader_eph_x.begin(), input.reader_eph_x.end());
    salt.insert(salt.end(), input.endpoint_eph_x.begin(), input.endpoint_eph_x.end());
    salt.insert(salt.end(), input.transaction_id.begin(), input.transaction_id.end());
    salt.push_back((uint8_t)ddk::TransportKind::Nfc);
    salt.push_back(input.flags[0]);
    salt.push_back(input.flags[1]);
    salt.insert(salt.end(), context.begin(), context.end());
    salt.push_back(0x5C);
    salt.push_back(input.version.size());
    salt.insert(salt.end(), input.version.begin(), input.version.end());
    salt.insert(salt.end(), kSupportedVersions.begin(), kSupportedVersions.end());
    return salt;
}
} // namespace

std::vector<uint8_t> HomeKeyKeySchedule::derive_fast_material(
    const SessionInput& input,
    ddk::span<const uint8_t> endpoint_pk_x,
    ddk::span<const uint8_t> persistent_key)
{
    auto salt = build_fast_salt(input, endpoint_pk_x);
    LOG_HEX(D, "Auth0 HKDF Material", salt);

    std::vector<uint8_t> okm(58);
    int ret = mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        nullptr, 0,
        persistent_key.data(), persistent_key.size(),
        salt.data(), salt.size(),
        okm.data(), okm.size());
    LOG(V, "HKDF Status: %d", ret);
    return okm;
}

HomeKeyKeySchedule::StandardResult HomeKeyKeySchedule::derive_standard(
    const SessionInput& input,
    ddk::span<const uint8_t,32> derived_key)
{
    StandardResult result{};

    {
        auto salt = build_standard_salt(input, kPersistent);
        mbedtls_hkdf(
            mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
            nullptr, 0,
            derived_key.data(), 32,
            salt.data(), salt.size(),
            result.persistent_key.data(), 32);
    }

    {
        auto salt = build_standard_salt(input, kVolatile);
        result.volatile_key.resize(48);
        mbedtls_hkdf(
            mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
            nullptr, 0,
            derived_key.data(), 32,
            salt.data(), salt.size(),
            result.volatile_key.data(), 48);
    }

    return result;
}
