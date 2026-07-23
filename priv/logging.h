#pragma once
#include <string>
#include <vector>
#include "fmt/format.h"
#include "fmt/ranges.h"
#if defined(CONFIG_IDF_CMAKE)
#include <esp_log.h>
#define LOG(x, format, ...) ESP_LOG##x(TAG, "%s:%d > " format, __FUNCTION__ , __LINE__ __VA_OPT__(, ) __VA_ARGS__)
#else 
#include <stdio.h>
#define LOG(x, format, ...) printf("%s:%d > " format "\n", __FUNCTION__ , __LINE__ __VA_OPT__(, ) __VA_ARGS__)
#endif

// LOG_HEX — gated hex dump for binary data. On ESP, ESP_LOG_BUFFER_HEX_LEVEL
// only emits when the active log level >= VERBOSE, so production builds skip
// the dump. On native, the loop is gated by an explicit VERBOSE comparison.
// Never changes data; only emits logs when VERBOSE is enabled.
#if defined(CONFIG_IDF_CMAKE)
#define LOG_HEX_BUF(label, data_ptr, data_len)                                  \
    do {                                                                    \
        LOG(V, "%s (len=%d)", label, (int)(data_len));                      \
        if ((data_ptr) != nullptr && (data_len) > 0) {                      \
            ESP_LOG_BUFFER_HEX_LEVEL(label, (data_ptr), (data_len), ESP_LOG_VERBOSE); \
        }                                                                   \
    } while (0)
#else
#define LOG_HEX(label, data_ptr, data_len)                                  \
    do {                                                                    \
        LOG(V, "%s (len=%d):", label, (int)(data_len));                     \
        for (size_t _i = 0; _i < (size_t)(data_len); ++_i)                  \
            printf("%02X", (data_ptr)[_i]);                                 \
        printf("\n");                                                       \
    } while (0)
#endif

#define LOG_HEX_FMT(level, msg, data) \
    LOG(level, msg ": %s", fmt::format("{:02X}", fmt::join(data, "")).c_str())

inline std::string redactHex(const char* label, const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) return std::string(label) + ": <empty>";
    std::string s = label;
    s += ": ";
    const size_t show = (len < 4) ? len : 4;
    for (size_t i = 0; i < show; ++i) {
        char hex[3];
        std::snprintf(hex, sizeof(hex), "%02X", data[i]);
        s += hex;
    }
    if (len > show) s += "…"; // UTF-8 ellipsis
    s += " (" + std::to_string(len) + " bytes)";
    return s;
}

// Overload for std::vector for convenience
inline std::string redactHex(const char* label, const std::vector<uint8_t>& data) {
    return redactHex(label, data.data(), data.size());
}
