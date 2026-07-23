/*
  Code highly inspired by https://github.com/kormax/apple-home-key-reader/blob/main/util/iso18013.py
 */
#pragma once
#ifndef ISO18013_SECURE_CONTEXT_H
#define ISO18013_SECURE_CONTEXT_H

#include <vector>
#include <cstdint>

class ISO18013SecureContext {
public:
    ISO18013SecureContext(const std::vector<uint8_t>& sharedSecret, const std::vector<uint8_t>& salt, size_t keyLength);
    ~ISO18013SecureContext();

    std::vector<uint8_t> getReaderIV() const;
    std::vector<uint8_t> getEndpointIV() const;

    std::vector<uint8_t> encryptMessageToEndpoint(const std::vector<uint8_t>& message);
    std::vector<uint8_t> decryptMessageFromEndpoint(const std::vector<uint8_t>& message);

private:
  const char *TAG = "ISO18013_SC";
  size_t keyLength;
  size_t readerCounter;
  size_t endpointCounter;
  std::vector<uint8_t> readerKey;
  std::vector<uint8_t> endpointKey;
};

#endif // ISO18013_SECURE_CONTEXT_H
