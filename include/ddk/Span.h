#pragma once
#include <cstddef>
#include <initializer_list>
#include <type_traits>

namespace ddk {

inline constexpr std::size_t dynamic_extent = static_cast<std::size_t>(-1);

namespace detail {
    template <typename From, typename To>
    using is_allowed_pointer_conversion =
        std::is_convertible<From(*)[], To(*)[]>;

    template <typename Container, typename ElementType, typename = void>
    struct is_compatible_container : std::false_type {};

    template <typename Container, typename ElementType>
    struct is_compatible_container<Container, ElementType, std::void_t<
        decltype(std::declval<Container&>().data()),
        decltype(std::declval<Container&>().size())
    >> : is_allowed_pointer_conversion<
            std::remove_pointer_t<decltype(std::declval<Container&>().data())>,
            ElementType
         > {};
} // namespace detail

template<typename T, std::size_t Extent = dynamic_extent>
class span {
public:
    using element_type    = T;
    using value_type      = std::remove_cv_t<T>;
    using size_type       = std::size_t;
    using pointer         = T*;
    using const_pointer   = const T*;
    using reference       = T&;
    using const_reference = const T&;
    using iterator        = pointer;

    // --- Constructors ---

    // Default: only valid for dynamic or zero extent.
    // static_assert is in the body — only checked when called,
    // not when the class is instantiated.
    constexpr span() noexcept : _data(nullptr), _size(0) {
        static_assert(Extent == dynamic_extent || Extent == 0,
                      "default constructor requires dynamic or zero extent");
    }

    constexpr span(pointer data, size_type count) noexcept
        : _data(data), _size(count) {}

    constexpr span(pointer first, pointer last) noexcept
        : _data(first), _size(static_cast<size_type>(last - first)) {}

    // Array constructor — compile-time check via static_assert
    // (template member, body instantiated only when called)
    template<std::size_t N>
    constexpr span(element_type (&arr)[N]) noexcept : _data(arr), _size(N) {
        static_assert(Extent == dynamic_extent || Extent == N,
                      "array size must match fixed extent");
    }

    // Container constructor (mutable lvalue)
    template<typename Container, typename = std::enable_if_t<
        !std::is_same_v<std::decay_t<Container>, span> &&
        detail::is_compatible_container<Container, element_type>::value
    >>
    constexpr span(Container& c) noexcept
        : _data(c.data()), _size(c.size()) {}

    // Container constructor (const lvalue)
    template<typename Container, typename = std::enable_if_t<
        !std::is_same_v<std::decay_t<Container>, span> &&
        detail::is_compatible_container<const Container, element_type>::value
    >>
    constexpr span(const Container& c) noexcept
        : _data(c.data()), _size(c.size()) {}

    // Converting constructor: span<U, OtherExtent> → span<T, Extent>
    // static_assert checks extent match (only when called)
    template<typename U, std::size_t OtherExtent, typename = std::enable_if_t<
        detail::is_allowed_pointer_conversion<U, element_type>::value
    >>
    constexpr span(const span<U, OtherExtent>& other) noexcept
        : _data(other.data()), _size(other.size()) {
        static_assert(Extent == dynamic_extent || Extent == OtherExtent,
                      "extent mismatch in converting constructor");
    }

    // initializer_list — no enable_if, type system handles const-ness
    constexpr span(std::initializer_list<std::remove_cv_t<element_type>> list) noexcept
        : _data(list.begin()), _size(list.size()) {}

    // --- Accessors ---

    constexpr pointer    data()       const noexcept { return _data; }
    constexpr size_type  size()       const noexcept { return _size; }
    constexpr size_type  size_bytes() const noexcept { return _size * sizeof(element_type); }
    constexpr bool       empty()      const noexcept { return _size == 0; }

    constexpr reference operator[](size_type idx) const { return _data[idx]; }
    constexpr reference front() const { return _data[0]; }
    constexpr reference back()  const { return _data[_size - 1]; }

    constexpr iterator begin() const noexcept { return _data; }
    constexpr iterator end()   const noexcept { return _data + _size; }

    // --- Subviews (always dynamic extent) ---

    constexpr span<element_type, dynamic_extent>
    subspan(size_type offset, size_type count = dynamic_extent) const {
        if (offset > _size) return {};
        if (count == dynamic_extent || count > _size - offset)
            count = _size - offset;
        return {_data + offset, count};
    }

    constexpr span<element_type, dynamic_extent>
    first(size_type n) const { return subspan(0, n); }

    constexpr span<element_type, dynamic_extent>
    last(size_type n) const {
        return subspan(_size > n ? _size - n : 0, n);
    }

private:
    pointer   _data;
    size_type _size;
};

// --- CTAD guides (deduce to dynamic extent) ---

template<typename T, std::size_t N>
span(T (&)[N]) -> span<T>;

template<typename Container>
span(Container&) -> span<typename Container::value_type>;

template<typename Container>
span(const Container&) -> span<const typename Container::value_type>;

}  // namespace ddk
