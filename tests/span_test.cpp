#include "ddk/Span.h"
#include <cassert>
#include <cstdint>
#include <vector>
#include <array>

int main() {
    std::vector<uint8_t> v = {1, 2, 3};
    ddk::span<const uint8_t> s(v);
    assert(s.size() == 3);
    assert(s[0] == 1);
    
    std::array<uint8_t,4> a = {4, 5, 6, 7};
    ddk::span<const uint8_t> sa(a);
    assert(sa.size() == 4);
    
    auto sub = sa.subspan(1, 2);
    assert(sub.size() == 2);
    assert(sub[0] == 5);
}
