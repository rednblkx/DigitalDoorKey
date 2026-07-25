#pragma once
#include <vector>
#include <array>
#include <algorithm>
#include <cstdint>
#include <initializer_list>

#if defined(CONFIG_IDF_CMAKE)
#include <mbedtls/platform_util.h>
#endif

inline void secure_zero(void* p, size_t len) {
    if (p && len > 0) {
#if defined(CONFIG_IDF_CMAKE)
        mbedtls_platform_zeroize(p, len);
#else
        volatile uint8_t* vp = (volatile uint8_t*)p;
        while (len--) *vp++ = 0;
#endif
    }
}

template <size_t N>
struct SecureBuffer {
    std::array<uint8_t, N> raw_data{};

    SecureBuffer() = default;
    
    SecureBuffer(const std::vector<uint8_t>& vec) {
        assign(vec.data(), vec.size());
    }

    template<size_t M>
    SecureBuffer(const std::array<uint8_t, M>& arr) {
        assign(arr.data(), M);
    }

    SecureBuffer(std::initializer_list<uint8_t> list) {
        assign(list.begin(), list.size());
    }

    ~SecureBuffer() { 
        secure_zero(raw_data.data(), N); 
    }
    SecureBuffer(const SecureBuffer& other) {
        std::copy(other.raw_data.begin(), other.raw_data.end(), raw_data.begin());
    }

    SecureBuffer(SecureBuffer&& other) noexcept {
        std::copy(other.raw_data.begin(), other.raw_data.end(), raw_data.begin());
        other.clear();
    }   
    SecureBuffer& operator=(const std::vector<uint8_t>& vec) {
        assign(vec.data(), vec.size());
        return *this;
    }

    template<size_t M>
    SecureBuffer& operator=(const std::array<uint8_t, M>& arr) {
        assign(arr.data(), M);
        return *this;
    }

    SecureBuffer& operator=(std::initializer_list<uint8_t> list) {
        assign(list.begin(), list.size());
        return *this;
    }

    SecureBuffer& operator=(const SecureBuffer& other) {
        if (this != &other) {
            std::copy(other.raw_data.begin(), other.raw_data.end(), raw_data.begin());
        }
        return *this;
    }

    operator std::array<uint8_t, N>&() {
      return raw_data;
    }

    uint8_t* data() { return raw_data.data(); }
    const uint8_t* data() const { return raw_data.data(); }
    uint8_t* begin() { return raw_data.data(); }
    uint8_t* end() { return raw_data.data() + N; }
    const uint8_t* begin() const { return raw_data.data(); }
    const uint8_t* end() const { return raw_data.data() + N; }
    size_t size() const { return N; }

    void assign(const uint8_t* src, size_t len) {
        if (!src || len == 0) {
            clear();
            return;
        }
        size_t to_copy = (len < N) ? len : N;
        std::copy_n(src, to_copy, raw_data.begin());
        if (N > to_copy) std::fill(raw_data.begin() + to_copy, raw_data.end(), 0);
    }

    template <typename InputIt>
    void assign(InputIt first, InputIt last) {
        size_t dist = std::distance(first, last);
        size_t to_copy = std::min(dist, N);
        std::copy_n(first, to_copy, raw_data.begin());
        if (N > to_copy) std::fill(raw_data.begin() + to_copy, raw_data.end(), 0);
    }

    template <typename InputIt>
    void insert(uint8_t* pos, InputIt first, InputIt last) {
        size_t dist = std::distance(first, last);
        size_t offset = std::distance(raw_data.data(), pos);
        if (offset >= N) return;
        size_t to_copy = std::min(dist, N - offset);
        std::copy_n(first, to_copy, raw_data.begin() + offset);
    }

    uint8_t& operator[](size_t i) { return raw_data[i]; }
    const uint8_t& operator[](size_t i) const { return raw_data[i]; }
    
    bool empty() const {
        for (auto b : raw_data) if (b != 0) return false;
        return true;
    }

    void clear() { std::fill(raw_data.begin(), raw_data.end(), 0); }
};

class SecureVector {
    std::vector<uint8_t> data_vec;
public:
    SecureVector() = default;
    SecureVector(size_t n) : data_vec(n, 0) {}
    SecureVector(const std::vector<uint8_t>& other) : data_vec(other) {}
    ~SecureVector() { if (!data_vec.empty()) secure_zero(data_vec.data(), data_vec.size()); }
    
    SecureVector& operator=(const std::vector<uint8_t>& vec) {
        data_vec = vec;
        return *this;
    }

    operator std::vector<uint8_t>() const { return data_vec; }
    operator const std::vector<uint8_t>&() const { return data_vec; }

    uint8_t* data() { return data_vec.data(); }
    const uint8_t* data() const { return data_vec.data(); }
    uint8_t* begin() { return data_vec.data(); }
    uint8_t* end() { return data_vec.data() + data_vec.size(); }
    const uint8_t* begin() const { return data_vec.data(); }
    const uint8_t* end() const { return data_vec.data() + data_vec.size(); }
    size_t size() const { return data_vec.size(); }
    void resize(size_t n) { data_vec.resize(n); }
    void assign(const uint8_t* src, size_t len) { data_vec.assign(src, src + len); }
    std::vector<uint8_t>& vec() { return data_vec; }
    const std::vector<uint8_t>& vec() const { return data_vec; }
};
