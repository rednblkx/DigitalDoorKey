// tests/span_test.cpp
#include "ddk/Span.h"
#include <cstdint>
#include <vector>
#include <type_traits>

static std::vector<uint8_t> make_vec() { return {1, 2, 3}; }

int main() {
    // lvalue containers — const and mutable
    std::vector<uint8_t> v = {1, 2, 3};
    ddk::span<const uint8_t> sc(v);
    ddk::span<uint8_t> sm(v);
    const std::vector<uint8_t> cv = {4, 5};
    ddk::span<const uint8_t> scc(cv);          // const lvalue → const span

    // rvalue → const span: allowed (the case that failed)
    ddk::span<const uint8_t> sr(make_vec());
    ddk::span<const uint8_t> sr2(std::vector<uint8_t>{7, 8});

    // arrays
    uint8_t a[4] = {9, 9, 9, 9};
    ddk::span<const uint8_t> sa(a);
    ddk::span<uint8_t> sam(a);

    // cross: mutable span → const span
    ddk::span<const uint8_t> sx(sm);

    (void)sc; (void)sm; (void)scc; (void)sr; (void)sr2;
    (void)sa; (void)sam; (void)sx;
}

// rvalue → MUTABLE span must NOT compile (dangling prevention)
static_assert(!std::is_constructible_v<ddk::span<uint8_t>, std::vector<uint8_t>>,
              "mutable span from rvalue container must be rejected");
static_assert(std::is_constructible_v<ddk::span<const uint8_t>, std::vector<uint8_t>>,
              "const span from rvalue container must be accepted");
static_assert(!std::is_constructible_v<ddk::span<uint8_t>, const std::vector<uint8_t>>,
              "mutable span from const container must be rejected");
