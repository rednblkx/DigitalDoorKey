#pragma once

#include <cstdio>
#include <iostream>
#include <list>      // Changed from forward_list
#include <vector>    // For value storage
#include <cstdint>
#include <ostream>
#include <iomanip>   // For printing hex
#include <algorithm> // For std::find_if
#include <cstring>   // For memcpy

// --- tlv_t Struct ---
// Represents a single Tag-Length-Value item
struct tlv_t {
    uint8_t tag;
    std::vector<uint8_t> value;

    // Constructor
    tlv_t(uint8_t t, std::vector<uint8_t> v) :
        tag(t), value(std::move(v)) {}

    // Constructor from raw data
    tlv_t(uint8_t t, const uint8_t* val_ptr, size_t len) : tag(t) {
        if (val_ptr && len > 0) {
            value.assign(val_ptr, val_ptr + len);
        }
    }

    // Getters
    size_t length() const { return value.size(); }
    const uint8_t* data() const { return value.data(); }
    uint8_t* data() { return value.data(); }
};

// --- Typedefs for Iterators ---
using list_type = std::list<tlv_t>;
using tlv_it = list_type::iterator;
using const_iterator = list_type::const_iterator;

// --- TLV Class ---
// Manages a collection of tlv_t items
class TLV8 {
private:
    list_type items; // Composition: Store items in a list
    bool use_ber_length_encoding = false; // Flag to control length encoding style (BER vs TLV8)
    bool parse_ok_ = true;                // Tracks whether the last parse() completed cleanly

    // Helper for hex conversion in errors
    static std::string to_hex(uint8_t val) {
        std::stringstream ss;
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(val);
        return ss.str();
    }

public:
    // --- Constructors ---

    TLV8(bool use_ber = false) : use_ber_length_encoding(use_ber) {}

    // --- Modifiers ---

    // Add a TLV item to the end
    tlv_it add(uint8_t tag, size_t len, const uint8_t* val) {
        items.emplace_back(tag, val, len);
        return --items.end(); // Return iterator to the added element
    }

    tlv_it add(uint8_t tag, std::vector<uint8_t> value) {
        items.emplace_back(tag, std::move(value));
        return --items.end();
    }

    // Convenience overloads for adding
    tlv_it add(uint8_t tag, uint8_t val) {
        uint8_t v[] = {val};
        return add(tag, 1, v);
    }
    tlv_it add(uint8_t tag) { return add(tag, 0, nullptr); }

    // Clear all items
    void clear() { items.clear(); }

    // --- Element Access / Search ---

    // Find the first TLV with the given tag in the whole list
    tlv_it find(uint8_t tag) {
        return std::find_if(
            items.begin(), items.end(), [tag](const tlv_t& item) { return item.tag == tag; }
        );
    }
    const_iterator find(uint8_t tag) const {
        return std::find_if(
            items.begin(), items.cend(), [tag](const tlv_t& item) { return item.tag == tag; }
        );
    }

    // Safe accessor: returns a pointer to the first item with the given tag,
    // or nullptr if not found (or if the parse failed). Use instead of
    // dereferencing find() directly to avoid UB on miss.
    tlv_t* expect(uint8_t tag) {
        tlv_it it = find(tag);
        return it == items.end() ? nullptr : &(*it);
    }
    const tlv_t* expect(uint8_t tag) const {
        const_iterator it = find(tag);
        return it == items.cend() ? nullptr : &(*it);
    }

    // Convenience: copies the value of the tag into `out` if present; returns
    // false on miss or after a failed parse.
    bool get(uint8_t tag, std::vector<uint8_t>& out) const {
        const tlv_t* item = expect(tag);
        if (item == nullptr) return false;
        out = item->value;
        return true;
    }

    // --- Capacity ---
    bool empty() const { return items.empty(); }
    size_t size() const { return items.size(); }

    // Reflects whether the most recent parse() completed without errors.
    bool ok() const { return parse_ok_; }
    explicit operator bool() const { return parse_ok_; }

    // --- Iterators ---
    tlv_it begin() { return items.begin(); }
    tlv_it end() { return items.end(); }
    const_iterator begin() const { return items.cbegin(); }
    const_iterator end() const { return items.cend(); }
    const_iterator cbegin() const { return items.cbegin(); }
    const_iterator cend() const { return items.cend(); }

    // --- Serialization ---

    // BER helper: calculate size needed for BER length encoding
    static size_t get_ber_length_field_size(size_t len) {
        if (len < 128) return 1;
        if (len <= 0xFF) return 2;
        if (len <= 0xFFFF) return 3;
        if (len <= 0xFFFFFF) return 4;
        return 5;
    }

    // BER helper: write BER length encoding
    static uint8_t* write_ber_length(uint8_t* buf, size_t len) {
        if (len < 128) {
            *buf++ = static_cast<uint8_t>(len);
        } else {
            size_t len_bytes = 0;
            if (len <= 0xFF) len_bytes = 1;
            else if (len <= 0xFFFF) len_bytes = 2;
            else if (len <= 0xFFFFFF) len_bytes = 3;
            else len_bytes = 4;

            *buf++ = static_cast<uint8_t>(0x80 | len_bytes);
            for (size_t i = 0; i < len_bytes; ++i) {
                buf[len_bytes - 1 - i] = static_cast<uint8_t>(len >> (i * 8));
            }
            buf += len_bytes;
        }
        return buf;
    }

    // Calculate the total packed size in bytes (BER or TLV8)
    size_t size_packed() const {
        size_t total_size = 0;
        if (use_ber_length_encoding) {
            // BER Size Calculation
            for (const auto& item : items) {
                total_size += 1; // Tag
                total_size += get_ber_length_field_size(item.length()); // Length
                total_size += item.length(); // Value
            }
        } else {
            // TLV8 Size Calculation
            for (const auto& item : items) {
                size_t item_len = item.length();
                if (item_len == 0) {
                    total_size += 2; // T + L=0
                } else {
                    // Calculate number of chunks (max 255 bytes each)
                    size_t num_chunks = (item_len + 254) / 255;
                    total_size += num_chunks * 2; // T+L for each chunk
                    total_size += item_len;       // Total value bytes
                }
            }
        }
        return total_size;
    }

    // Pack all TLV items into the provided buffer (BER or TLV8)
    size_t get(uint8_t* buffer, size_t buffer_size) const {
        size_t required_size = size_packed();
        if (buffer_size < required_size) {
            printf(
                "%s", ("Buffer too small for packing. Required: " +
                std::to_string(required_size) +
                ", Available: " + std::to_string(buffer_size)).c_str()
            );
        }

        uint8_t* start_pos = buffer;
        uint8_t* current_pos = buffer;
        const uint8_t* buffer_end = buffer + buffer_size; // For bounds checking

        if (use_ber_length_encoding) {
            // --- BER Packing ---
            for (const auto& item : items) {
                // Bounds check before writing Tag + Length field
                 size_t min_tl_size = 1 + get_ber_length_field_size(item.length());
                 if (current_pos + min_tl_size > buffer_end) goto pack_overflow;

                // Write Tag
                *current_pos++ = item.tag;
                // Write Length (BER encoded)
                current_pos = write_ber_length(current_pos, item.length());
                // Write Value
                if (item.length() > 0) {
                    if (current_pos + item.length() > buffer_end) goto pack_overflow;
                    memcpy(current_pos, item.data(), item.length());
                    current_pos += item.length();
                }
            }
        } else {
            // --- TLV8 Packing ---
            for (const auto& item : items) {
                const uint8_t* value_ptr = item.data();
                size_t remaining_len = item.length();
                uint8_t tag = item.tag;

                if (remaining_len == 0) {
                    // Handle zero-length value
                    if (current_pos + 2 > buffer_end) goto pack_overflow;
                    *current_pos++ = tag;
                    *current_pos++ = 0; // Length 0
                } else {
                    // Handle non-zero length value (split into chunks)
                    while (remaining_len > 0) {
                        uint8_t chunk_len = (remaining_len > 255) ? 255 : static_cast<uint8_t>(remaining_len);

                        // Bounds check for T + L + ValueChunk
                        if (current_pos + 2 + chunk_len > buffer_end) goto pack_overflow;

                        // Write Tag
                        *current_pos++ = tag;
                        // Write Length (single byte, max 255)
                        *current_pos++ = chunk_len;
                        // Write Value Chunk
                        memcpy(current_pos, value_ptr, chunk_len);
                        current_pos += chunk_len;
                        value_ptr += chunk_len;
                        remaining_len -= chunk_len;
                    }
                }
            }
        }

        return current_pos - start_pos; // Return bytes written

    pack_overflow:
         // Should not happen if pack_size() is correct and buffer_size check passed,
         // but good for robustness.
         printf("Internal packing error: Buffer overflow detected.");
         return 0;
    }

    // Convenience overload to pack into a new vector
    std::vector<uint8_t> get() const {
        std::vector<uint8_t> buffer(size_packed());
        get(buffer.data(), buffer.size());
        return buffer;
    }

    // --- Unpacking (Deserialization) ---

    // Unpack TLV items from the buffer (BER or TLV8)
    void parse(const uint8_t* buffer, size_t buffer_size) {
        items.clear();
        parse_ok_ = false;
        const uint8_t* current_pos = buffer;
        const uint8_t* end_pos = buffer + buffer_size;

        while (current_pos < end_pos) {
            // Read Tag
            if (current_pos + 1 > end_pos) {
                printf("Unpack error: Insufficient data for tag");
                return;
            }
            uint8_t tag = *current_pos++;

            // Read Length (Handles BER long form if flag is set)
            if (current_pos + 1 > end_pos) {
                printf(
                    "%s", ("Unpack error: Insufficient data for length byte (tag: 0x" +
                    to_hex(tag) + ")").c_str()
                );
                return;
            }
            size_t len = 0;
            uint8_t len_byte = *current_pos++;

            if (use_ber_length_encoding && (len_byte & 0x80)) {
                // BER Long Form Length
                size_t len_bytes_count = len_byte & 0x7F;
                if (len_bytes_count == 0 || len_bytes_count > sizeof(size_t)) {
                    printf("%s", (
                        "Unpack error: Unsupported BER length form (tag: 0x" +
                        to_hex(tag) + ", len_byte: 0x" + to_hex(len_byte) + ")").c_str()
                    );
                    return;
                }
                if (current_pos + len_bytes_count > end_pos) {
                    printf(
                        "%s", ("Unpack error: Insufficient data for BER long length value (tag: 0x" +
                        to_hex(tag) + ")").c_str()
                    );
                    return;
                }
                len = 0;
                for (size_t i = 0; i < len_bytes_count; ++i) {
                    len = (len << 8) | (*current_pos++);
                }
            } else {
                // Simple Length (TLV8 or BER Short Form)
                len = len_byte;
            }

            // Read Value Data Pointer (don't copy yet)
            if (current_pos + len > end_pos) {
                printf(
                    "%s", ("Unpack error: Insufficient data for value (tag: 0x" +
                    to_hex(tag) + ", length: " + std::to_string(len) + ")").c_str()
                );
                return;
            }
            const uint8_t* value_start_ptr = current_pos;

            // Add/Merge Item
            if (!use_ber_length_encoding && !items.empty() && items.back().tag == tag) {
                // TLV8 Mode: Merge with previous item if tags match
                tlv_t& last_item = items.back();
                // Append new data chunk to the existing value vector
                last_item.value.insert(
                    last_item.value.end(), value_start_ptr, value_start_ptr + len
                );
            } else {
                // BER Mode or TLV8 Mode (first item or different tag): Add new item
                items.emplace_back(tag, value_start_ptr, len);
            }

            // Advance position past value
            current_pos += len;
        }

        if (current_pos != end_pos) {
            // Could indicate trailing garbage data. Add warning/error if needed.
            std::cerr << "Warning: Trailing data left after unpacking." << std::endl;
            return;
        }

        parse_ok_ = true;
    }
};