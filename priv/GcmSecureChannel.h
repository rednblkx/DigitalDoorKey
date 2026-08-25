#pragma once
#include "SecureBuffer.h"
#include <array>
#include <cstdint>
#include <vector>

class GcmSecureChannel {
public:
    GcmSecureChannel(const std::array<uint8_t,32> &sk_reader,
                     const std::array<uint8_t,32> &sk_device,
                     uint32_t counter_reader = 1,
                     uint32_t counter_endpoint = 1);

    // Raw data — used by ENVELOPE (0xC3) and AUTH1 decrypt
    std::vector<uint8_t> encrypt_reader_data(const std::vector<uint8_t> &plaintext);
    std::vector<uint8_t> decrypt_endpoint_data(const std::vector<uint8_t> &ciphertext);

    // APDU-wrapped — used by EXCHANGE (0xC9)
    struct EncryptedCommand {
        std::vector<uint8_t> data;  // encrypted data field
        uint32_t counter;
    };
    struct DecryptedResponse {
        std::vector<uint8_t> data;  // decrypted plaintext
        uint32_t counter;
    };
    EncryptedCommand  encrypt_command(const std::vector<uint8_t> &command_data);
    DecryptedResponse decrypt_response(const std::vector<uint8_t> &response_data);

    uint32_t counter_reader()   const { return counter_reader_; }
    uint32_t counter_endpoint() const { return counter_endpoint_; }

private:
    const char *TAG = "GcmSecureChannel";
    SecureBuffer<32> sk_reader_;
    SecureBuffer<32> sk_device_;
    uint32_t counter_reader_;
    uint32_t counter_endpoint_;

    static constexpr std::array<uint8_t,8> kReaderMode{0,0,0,0,0,0,0,0};
    static constexpr std::array<uint8_t,8> kEndpointMode{0,0,0,0,0,0,0,1};

    std::array<uint8_t,12> make_iv_reader() const;
    std::array<uint8_t,12> make_iv_endpoint() const;
};
