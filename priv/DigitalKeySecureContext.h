/*
  Code highly inspired by https://github.com/kormax/apple-home-key-reader/blob/main/util/digital_key.py
 */

#ifndef DIGITAL_KEY_SECURE_CONTEXT_H
#define DIGITAL_KEY_SECURE_CONTEXT_H

#include <array>
#include <tuple>
#include <vector>
#include <cstdint>

class DigitalKeySecureContext {
public:
    DigitalKeySecureContext() = default;
    DigitalKeySecureContext(const std::vector<uint8_t> &volatileKey);
    DigitalKeySecureContext(const std::array<uint8_t,32> *skReader, const std::array<uint8_t,32> *skDevice);
    ~DigitalKeySecureContext();

    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> encrypt_command(unsigned char* data, size_t dataSize);
    std::vector<uint8_t> decrypt_response(const unsigned char* data, size_t dataSize);

private:
    const char *TAG = "DigitalKeySC";
    int device_counter{};
    unsigned char mac_chaining_value[16] = {0x0, 0x0, 0x0, 0x0, 0x0 ,0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    unsigned char command_pcb[15] = {0x0, 0x0, 0x0, 0x0, 0x0 ,0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    unsigned char response_pcb[15] = {0x80, 0x0, 0x0, 0x0, 0x0 ,0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    unsigned char kenc[16]{};
    unsigned char kmac[16]{};
    unsigned char krmac[16]{};
    const std::array<uint8_t,32> *skReader = nullptr;
    const std::array<uint8_t,32> *skDevice = nullptr;
    bool useAliro = false;
    const std::array<uint8_t, 8> READER_MODE = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const std::array<uint8_t, 8> ENDPOINT_MODE = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    std::vector<uint8_t> encrypt(unsigned char* plaintext, size_t data_size, const unsigned char* pcb, const unsigned char* key);
    std::vector<uint8_t> decrypt(const unsigned char* ciphertext, size_t data_size, const unsigned char* pcb, const unsigned char* key);
    std::tuple<std::vector<uint8_t>, size_t> pad_mode_3(unsigned char* message, size_t message_size, unsigned char pad_byte, size_t block_size);
    int unpad_mode_3(unsigned char* message, size_t message_size, unsigned char pad_flag_byte, size_t block_size);
    int encrypt_aes_cbc(const unsigned char* key, unsigned char* iv, const unsigned char* plaintext, size_t length, unsigned char* ciphertext);
    int decrypt_aes_cbc(const unsigned char* key, unsigned char* iv, const unsigned char* ciphertext, size_t length, unsigned char* plaintext);
    int aes_cmac(const unsigned char* key, const unsigned char* data, size_t data_size, unsigned char* mac);
    std::vector<uint8_t> concatenate_arrays(const unsigned char* a, const unsigned char* b, size_t size_a, size_t size_b);
};

#endif
