#pragma once
#include "ddk/transport/ApduChannel.h"
#include "DDKLogging.h"
#include <algorithm>

// Command chaining (CLA 0x10 chunks) + response chaining (GET RESPONSE
// reassembly) over any single-shot ApduChannel. Shared by NfcChannel and
// BleChannel

namespace ddk::detail {

constexpr const char* TAG = "ApduChaining";
constexpr uint8_t  kChainingClaBit        = 0x10;
constexpr size_t   kDefaultMaxResponseData = 256;
constexpr size_t   kMaxPreChainingPayload  = 2000;
constexpr uint8_t  kInsGetResponse         = 0xC0;

inline ApduResponse transceive_with_chaining(
    ApduChannel& channel, const ApduCommand& cmd,
    bool skip_response_chaining, size_t max_command_chunk)
{
    if (cmd.data.size() > kMaxPreChainingPayload) {
        LOG(E, "payload %zu exceeds pre-chaining limit %zu", cmd.data.size(),
            kMaxPreChainingPayload);
        return {{}, 0x6F, 0x00};
    }
    if (max_command_chunk == 0)
        max_command_chunk = 255;

    const size_t total_chunks = std::max<size_t>(
        1, (cmd.data.size() + max_command_chunk - 1) / max_command_chunk);

    ApduResponse response{};
    uint8_t last_cla = cmd.cla;

    // --- Command chaining ---
    for (size_t i = 0; i < total_chunks; ++i) {
        const bool is_last = (i == total_chunks - 1);
        const size_t start = i * max_command_chunk;
        const size_t end = std::min(start + max_command_chunk, cmd.data.size());

        ApduCommand chunk = cmd;
        chunk.data.assign(cmd.data.begin() + start, cmd.data.begin() + end);
        if (!is_last) {
            chunk.cla |= kChainingClaBit;
            chunk.ne = 0;
        }
        last_cla = chunk.cla;

        const bool extended = chunk.data.size() > 255 || (is_last && cmd.ne > 256);
        response = channel.transceive(chunk.to_bytes(extended));

        if (!is_last && !response.ok()) {
            LOG(E, "chained command %zu/%zu rejected: SW=%02X%02X", i + 1,
                total_chunks, response.sw1, response.sw2);
            return response;
        }
    }

    if (skip_response_chaining || response.sw1 != 0x61) {
        return response;
    }

    // --- Response chaining: GET RESPONSE loop ---
    // Initial response's data counts toward the assembled payload.
    std::vector<uint8_t> assembled = std::move(response.data);
    while (response.sw1 == 0x61) {
        ApduCommand get_response{
            last_cla,
            kInsGetResponse,
            0x00,
            0x00,
            {},
            static_cast<uint16_t>(response.sw2 == 0 ? 256 : response.sw2)};
        response = channel.transceive(get_response.to_bytes(false));

        if (response.data.size() > kDefaultMaxResponseData) {
            LOG(E, "GET RESPONSE chunk %zu exceeds device max", response.data.size());
            return {{}, 0x6F, 0x00};
        }
        assembled.insert(assembled.end(), response.data.begin(),
                        response.data.end());
        if (assembled.size() > kMaxPreChainingPayload) {
            LOG(E, "assembled response exceeds limit");
            return {{}, 0x6F, 0x00};
        }
    }

    return {std::move(assembled), response.sw1, response.sw2};
}

}  // namespace ddk::detail
