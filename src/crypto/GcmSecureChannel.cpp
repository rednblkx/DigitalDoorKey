#include "GcmSecureChannel.h"
#include "CommonCryptoUtils.h"
#include "DDKLogging.h"

GcmSecureChannel::GcmSecureChannel(
    const std::array<uint8_t,32> &sk_reader,
    const std::array<uint8_t,32> &sk_device,
    uint32_t counter_reader, uint32_t counter_endpoint)
    : counter_reader_(counter_reader), counter_endpoint_(counter_endpoint) {
    sk_reader_.assign(sk_reader.data(), 32);
    sk_device_.assign(sk_device.data(), 32);
}

std::array<uint8_t,12> GcmSecureChannel::make_iv_reader() const {
    std::array<uint8_t,12> iv{};
    std::copy(kReaderMode.begin(), kReaderMode.end(), iv.begin());
    iv[8]  = (counter_reader_ >> 24) & 0xFF;
    iv[9]  = (counter_reader_ >> 16) & 0xFF;
    iv[10] = (counter_reader_ >> 8)  & 0xFF;
    iv[11] = counter_reader_         & 0xFF;
    return iv;
}

std::array<uint8_t,12> GcmSecureChannel::make_iv_endpoint() const {
    std::array<uint8_t,12> iv{};
    std::copy(kEndpointMode.begin(), kEndpointMode.end(), iv.begin());
    iv[8]  = (counter_endpoint_ >> 24) & 0xFF;
    iv[9]  = (counter_endpoint_ >> 16) & 0xFF;
    iv[10] = (counter_endpoint_ >> 8)  & 0xFF;
    iv[11] = counter_endpoint_         & 0xFF;
    return iv;
}

std::vector<uint8_t> GcmSecureChannel::encrypt_reader_data(
    const std::vector<uint8_t> &plaintext, ddk::span<const uint8_t> aad) {
    if (plaintext.empty()) return {};
    auto iv = make_iv_reader();
    auto ct = CommonCryptoUtils::encryptAesGcm(plaintext, sk_reader_, iv, aad);
    counter_reader_++;
    return ct;
}

std::vector<uint8_t> GcmSecureChannel::decrypt_endpoint_data(
    const std::vector<uint8_t> &ciphertext, ddk::span<const uint8_t> aad) {
    if (ciphertext.empty()) return {};
    auto iv = make_iv_endpoint();
    auto pt = CommonCryptoUtils::decryptAesGcm(ciphertext, sk_device_, iv, aad);
    if (!pt.empty()) {
        counter_endpoint_++;
    } else {
        LOG(E, "GCM decrypt failed (tag verification)");
    }
    return pt;
}

GcmSecureChannel::EncryptedCommand GcmSecureChannel::encrypt_command(
    const std::vector<uint8_t> &command_data) {
    auto ct = encrypt_reader_data(command_data);
    return {std::move(ct), counter_reader_};
}

GcmSecureChannel::DecryptedResponse GcmSecureChannel::decrypt_response(
    const std::vector<uint8_t> &response_data) {
    auto pt = decrypt_endpoint_data(response_data);
    return {std::move(pt), counter_endpoint_};
}

// Device-role primitives: same IV scheme, mirrored direction. Used by
// BleMessageSecurity when running on the user-device side (tests).

std::vector<uint8_t> GcmSecureChannel::encrypt_endpoint_data(
    const std::vector<uint8_t> &plaintext, ddk::span<const uint8_t> aad) {
    if (plaintext.empty()) return {};
    auto ct = CommonCryptoUtils::encryptAesGcm(plaintext, sk_device_, make_iv_endpoint(), aad);
    counter_endpoint_++;
    return ct;
}

std::vector<uint8_t> GcmSecureChannel::decrypt_reader_data(
    const std::vector<uint8_t> &ciphertext, ddk::span<const uint8_t> aad) {
    if (ciphertext.empty()) return {};
    auto pt = CommonCryptoUtils::decryptAesGcm(ciphertext, sk_reader_, make_iv_reader(), aad);
    if (!pt.empty()) {
        counter_reader_++;
    } else {
        LOG(E, "GCM decrypt failed (tag verification)");
    }
    return pt;
}
