#pragma once

#include <string>
#include <cstdio>
#include <stdint.h>

#if defined(CONFIG_IDF_CMAKE)
#include <esp_log.h>
#else
#include <cstdio>
#endif

namespace DDK {

class Logger {
public:
    static std::string formatRedacted(const char* label, const void* data_ptr, size_t len) {
        const uint8_t* data = static_cast<const uint8_t*>(data_ptr);
        if (!data || len == 0) return std::string(label) + ": <empty>";
        
        char buf[2048];
        int written = 0;
        
#if defined(CONFIG_DDK_LOG_FULL_HEX) || defined(DDK_DEBUG_FULL_HEX)
        constexpr bool full_hex = true;
#else
        constexpr bool full_hex = false;
#endif

        if (label && label[0] != '\0') {
            written += std::snprintf(buf + written, sizeof(buf) - written, "%s: ", label);
        }

        if (full_hex) {
            for (size_t i = 0; i < len && (size_t)written < sizeof(buf) - 10; ++i) {
                written += std::snprintf(buf + written, sizeof(buf) - written, "%02X", data[i]);
            }
        } else {
            size_t show = (len < 8) ? len : 8;
            for (size_t i = 0; i < show; ++i) {
                written += std::snprintf(buf + written, sizeof(buf) - written, "%02X", data[i]);
            }
            if (len > show) {
                written += std::snprintf(buf + written, sizeof(buf) - written, "...");
            }
        }
        
        std::snprintf(buf + written, sizeof(buf) - written, " (%zu bytes)", len);
        return std::string(buf);
    }

    // Overload for containers
    template <typename T>
    static auto formatRedacted(const char* label, const T& container) 
        -> decltype(container.data(), container.size(), std::string()) {
        return formatRedacted(label, container.data(), container.size());
    }

    // Overload for raw arrays of any type
    template <typename T, size_t N>
    static std::string formatRedacted(const char* label, const T (&data)[N]) {
        return formatRedacted(label, static_cast<const void*>(data), N * sizeof(T));
    }
};

} // namespace DDK

#if defined(CONFIG_IDF_CMAKE)
    #define DDK_LOG(level, tag, fmt, ...) ESP_LOG##level(tag, "[%s:%d] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
    #define DDK_LOG(level, tag, fmt, ...) std::printf("[%s][%s][%s:%d] " fmt "\n", #level, tag, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#define LOG_HEX(level, label, data) \
    DDK_LOG(level, TAG, "%s", DDK::Logger::formatRedacted(label, data).c_str())

#ifndef LOG
#define LOG(level, fmt, ...) DDK_LOG(level, TAG, fmt, ##__VA_ARGS__)
#endif

#ifndef redactHex
#define redactHex_2(label, data) DDK::Logger::formatRedacted(label, data)
#define redactHex_3(label, data, len) DDK::Logger::formatRedacted(label, data, len)
#define GET_REDACT_MACRO(_1, _2, _3, NAME, ...) NAME
#define redactHex(...) GET_REDACT_MACRO(__VA_ARGS__, redactHex_3, redactHex_2)(__VA_ARGS__)
#endif

