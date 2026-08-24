#pragma once
#include <cstddef>
#include <type_traits>

#if defined(__cpp_lib_span) && __has_include(<span>)
#include <span>
namespace ddk {
template <typename T, std::size_t Extent = std::dynamic_extent>
using span = std::span<T, Extent>;
inline constexpr std::size_t dynamic_extent = std::dynamic_extent;
}
#else
namespace ddk {
inline constexpr std::size_t dynamic_extent = static_cast<std::size_t>(-1);

template <typename T, std::size_t Extent = dynamic_extent>
class span {
public:
    using element_type    = T;
    using value_type      = std::remove_cv_t<T>;
    using size_type       = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer         = T*;
    using const_pointer   = const T*;
    using reference       = T&;
    using const_reference = const T&;
    using iterator        = pointer;

    constexpr span() noexcept : data_(nullptr), size_(0) {}
    constexpr span(pointer ptr, size_type count) noexcept
        : data_(ptr), size_(count) {}
    constexpr span(pointer first, pointer last) noexcept
        : data_(first), size_(static_cast<size_type>(last - first)) {}

    template <std::size_t N>
    constexpr span(element_type (&arr)[N]) noexcept
        : data_(arr), size_(N) {}

    template <typename C,
              typename = std::enable_if_t<
                  !std::is_same_v<std::decay_t<C>, span> &&
                  std::is_convertible_v<decltype(std::declval<C>().data()), pointer>>>
    constexpr span(C& c) noexcept : data_(c.data()), size_(c.size()) {}

    constexpr iterator begin() const { return data_; }
    constexpr iterator end()   const { return data_ + size_; }
    constexpr pointer   data() const { return data_; }
    constexpr size_type  size() const { return size_; }
    constexpr size_type  size_bytes() const { return size_ * sizeof(T); }
    constexpr bool       empty() const { return size_ == 0; }
    constexpr reference  operator[](size_type idx) const { return data_[idx]; }
    constexpr reference  front() const { return data_[0]; }
    constexpr reference  back()  const { return data_[size_ - 1]; }

    constexpr span<element_type, dynamic_extent> first(size_type n) const {
        return {data_, n};
    }
    constexpr span<element_type, dynamic_extent> last(size_type n) const {
        return {data_ + size_ - n, n};
    }
    constexpr span<element_type, dynamic_extent> subspan(
        size_type offset, size_type count = dynamic_extent) const {
        return {data_ + offset, count == dynamic_extent ? size_ - offset : count};
    }

private:
    pointer   data_;
    size_type size_;
};
}  // namespace ddk
#endif
