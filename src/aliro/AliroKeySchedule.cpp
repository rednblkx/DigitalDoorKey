#include "aliro/AliroKeySchedule.h"
#include "DDKLogging.h"
#include <algorithm>
#include <cstring>
#include <mbedtls/hkdf.h>
#include <vector>

namespace {
constexpr const char* kVolatileFast = "VolatileFast";
constexpr const char* kVolatile    = "Volatile****";
constexpr const char* kPersistent   = "Persistent**";
constexpr const char* TAG           = "AliroKeySchedule";

std::vector<uint8_t> build_fast_salt(
    const AliroKeySchedule::SessionInput& input,
    ddk::span<const uint8_t> endpoint_pk_x)
{
    std::vector<uint8_t> salt;
    salt.reserve(input.reader_pk_x.size() + strlen(kVolatileFast) +
                 input.reader_identifier.size() + 1 + 4 +
                 input.reader_eph_x.size() + input.transaction_id.size() +
                 2 + 2 + input.fci_proprietary.size() + endpoint_pk_x.size());

    salt.insert(salt.end(), input.reader_pk_x.begin(), input.reader_pk_x.end());
    salt.insert(salt.end(), (const uint8_t*)kVolatileFast,
                (const uint8_t*)kVolatileFast + strlen(kVolatileFast));
    salt.insert(salt.end(), input.reader_identifier.begin(), input.reader_identifier.end());
    salt.push_back(input.interface);
    salt.push_back(0x5C);
    salt.push_back(input.version.size());
    salt.insert(salt.end(), input.version.begin(), input.version.end());
    salt.insert(salt.end(), input.reader_eph_x.begin(), input.reader_eph_x.end());
    salt.insert(salt.end(), input.transaction_id.begin(), input.transaction_id.end());
    salt.push_back(input.flags[0]);
    salt.push_back(input.flags[1]);
    salt.insert(salt.end(), input.fci_proprietary.begin(), input.fci_proprietary.end());
    salt.insert(salt.end(), endpoint_pk_x.begin(), endpoint_pk_x.end());
    return salt;
}

std::vector<uint8_t> build_standard_salt(
    const AliroKeySchedule::SessionInput& input,
    std::string_view context,
    ddk::span<const uint8_t> endpoint_pk_x)
{
    std::vector<uint8_t> salt;
    salt.reserve(input.reader_pk_x.size() + context.size() +
                 input.reader_identifier.size() + 1 + 4 +
                 input.reader_eph_x.size() + input.transaction_id.size() +
                 2 + 2 + input.fci_proprietary.size() +
                 (context == kPersistent ? endpoint_pk_x.size() : 0));

    salt.insert(salt.end(), input.reader_pk_x.begin(), input.reader_pk_x.end());
    salt.insert(salt.end(), context.begin(), context.end());
    salt.insert(salt.end(), input.reader_identifier.begin(), input.reader_identifier.end());
    salt.push_back(input.interface);
    salt.push_back(0x5C);
    salt.push_back(input.version.size());
    salt.insert(salt.end(), input.version.begin(), input.version.end());
    salt.insert(salt.end(), input.reader_eph_x.begin(), input.reader_eph_x.end());
    salt.insert(salt.end(), input.transaction_id.begin(), input.transaction_id.end());
    salt.push_back(input.flags[0]);
    salt.push_back(input.flags[1]);
    salt.insert(salt.end(), input.fci_proprietary.begin(), input.fci_proprietary.end());
    if (context == kPersistent) {
        salt.insert(salt.end(), endpoint_pk_x.begin(), endpoint_pk_x.end());
    }
    return salt;
}
} // namespace

AliroKeySchedule::FastResult AliroKeySchedule::derive_fast(
    const SessionInput& input,
    ddk::span<const uint8_t> endpoint_pk_x,
    ddk::span<const uint8_t> persistent_key)
{
    auto salt = build_fast_salt(input, endpoint_pk_x);
    LOG_HEX(D, "Auth0 HKDF Salt", salt);

    std::vector<uint8_t> okm(160);
    int ret = mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        salt.data(), salt.size(),
        persistent_key.data(), persistent_key.size(),
        input.endpoint_eph_x.data(), input.endpoint_eph_x.size(),
        okm.data(), okm.size());
    LOG(V, "HKDF Status: %d", ret);

    FastResult result{};
    std::copy_n(okm.data() + 0x00, 32, result.cryptogram_sk.begin());
    std::copy_n(okm.data() + 0x20, 32, result.exchange_sk_reader.begin());
    std::copy_n(okm.data() + 0x40, 32, result.exchange_sk_device.begin());
    std::copy_n(okm.data() + 0x60, 32, result.ble_sk.begin());
    std::copy_n(okm.data() + 0x80, 32, result.uwb_ranging_sk.begin());
    return result;
}

AliroKeySchedule::VolatileResult AliroKeySchedule::derive_volatile(
    const SessionInput& input,
    ddk::span<const uint8_t,32> derived_key)
{
    VolatileResult result{};
    auto salt = build_standard_salt(input, kVolatile, {});  // no endpoint_pk_x for volatile
    std::vector<uint8_t> okm(160);
    mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        salt.data(), salt.size(),
        derived_key.data(), 32,
        input.endpoint_eph_x.data(), input.endpoint_eph_x.size(),
        okm.data(), 160);
    std::copy_n(okm.data() + 0x00, 32, result.exchange_sk_reader.begin());
    std::copy_n(okm.data() + 0x20, 32, result.exchange_sk_device.begin());
    std::copy_n(okm.data() + 0x60, 32, result.ble_sk.begin());
    std::copy_n(okm.data() + 0x80, 32, result.uwb_ranging_sk.begin());
    std::array<uint8_t,32> step_up_input{};
    std::copy_n(okm.data() + 0x40, 32, step_up_input.data());
    constexpr std::array<uint8_t,32> kZeroSalt{};
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), kZeroSalt.data(), 32, step_up_input.data(), 32,
                (const uint8_t*)"SKReader", 8, result.step_up_sk_reader.data(), 32);
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), kZeroSalt.data(), 32, step_up_input.data(), 32,
                (const uint8_t*)"SKDevice", 8, result.step_up_sk_device.data(), 32);
    return result;
}

std::array<uint8_t,32> AliroKeySchedule::derive_persistent(
    const SessionInput& input,
    ddk::span<const uint8_t,32> derived_key,
    ddk::span<const uint8_t> endpoint_pk_x)
{
    std::array<uint8_t,32> result{};
    auto salt = build_standard_salt(input, kPersistent, endpoint_pk_x);
    mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        salt.data(), salt.size(),
        derived_key.data(), 32,
        input.endpoint_eph_x.data(), input.endpoint_eph_x.size(),
        result.data(), 32);
    return result;
}

AliroKeySchedule::BleSessionKeys AliroKeySchedule::derive_ble_session_keys(
    ddk::span<const uint8_t> ble_sk,
    ddk::span<const uint8_t> reader_supported_versions,
    ddk::span<const uint8_t> device_selected_versions)
{
    std::vector<uint8_t> salt;
    salt.reserve(reader_supported_versions.size() + device_selected_versions.size());
    salt.insert(salt.end(), reader_supported_versions.begin(), reader_supported_versions.end());
    salt.insert(salt.end(), device_selected_versions.begin(), device_selected_versions.end());

    BleSessionKeys out{};
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                 salt.data(), salt.size(),
                 ble_sk.data(), ble_sk.size(),
                 (const uint8_t*)"BleSKReader", 11, out.sk_reader.data(), 32);
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                 salt.data(), salt.size(),
                 ble_sk.data(), ble_sk.size(),
                 (const uint8_t*)"BleSKDevice", 11, out.sk_device.data(), 32);
    return out;
}
