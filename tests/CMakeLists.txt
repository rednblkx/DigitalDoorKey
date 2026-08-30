# Host-side test project for the DigitalDoorKey component.
#
# Standalone on purpose: configure/build/test it without any ESP-IDF:
#   cmake -S tests -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build --parallel
#   ctest --test-dir build --output-on-failure
#
# All third-party dependencies come via FetchContent, so CI needs nothing
# but a C/C++ toolchain. The component sources under test are listed
# explicitly — the two ESP-only translation units (src/homekey/Profile.cpp,
# src/auth/AttestationAuth.cpp with unguarded esp_* includes) are not part
# of the Aliro flows and are deliberately excluded.
cmake_minimum_required(VERSION 3.16)
project(ddk_host_tests LANGUAGES C CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

# --- Dependencies -----------------------------------------------------------

# mbedtls 3.6.6 — pinned release tarball (matches the ESP-IDF component's
# mbedtls 3.6.x and is self-contained, i.e. no git submodules needed).
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBED_LIBRARY OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_Declare(mbedtls
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.6/mbedtls-3.6.6.tar.bz2
    URL_HASH SHA256=8fb65fae8dcae5840f793c0a334860a411f884cc537ea290ce1c52bb64ca007a)

include(ExternalProject)
ExternalProject_Add(libsodium
    URL https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz
    URL_HASH SHA256=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19
    PREFIX ${FETCHCONTENT_BASE_DIR}/libsodium
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=<INSTALL_DIR> --enable-static --disable-shared
    BUILD_COMMAND make -j4
    INSTALL_COMMAND make install
    BUILD_BYPRODUCTS <INSTALL_DIR>/lib/libsodium.a
)
file(MAKE_DIRECTORY ${FETCHCONTENT_BASE_DIR}/libsodium/include)
add_library(sodium STATIC IMPORTED GLOBAL)
set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION ${FETCHCONTENT_BASE_DIR}/libsodium/lib/libsodium.a
    INTERFACE_INCLUDE_DIRECTORIES ${FETCHCONTENT_BASE_DIR}/libsodium/include)

# tinycbor — CBOR encode/decode (same version as the IDF managed component).
FetchContent_Declare(tinycbor
    GIT_REPOSITORY https://github.com/intel/tinycbor.git
    GIT_TAG        v0.6.0
    GIT_SHALLOW    TRUE)

# Catch2 v3 — test framework for the new flow tests.
set(CATCH_INSTALL_EXTRAS OFF CACHE BOOL "" FORCE)
set(CATCH_INSTALL_DOCS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.7.1
    GIT_SHALLOW    TRUE)

FetchContent_MakeAvailable(mbedtls tinycbor catch2)

# tinycbor v0.6.0 has no CMakeLists.txt at its repo root (Makefile-based
# upstream build), so FetchContent populated the sources without creating
# a target. Build the parser/encoder into a static lib here.
file(GLOB TINYCBOR_SOURCES ${tinycbor_SOURCE_DIR}/src/*.c)
add_library(tinycbor STATIC ${TINYCBOR_SOURCES})
target_include_directories(tinycbor PUBLIC ${tinycbor_SOURCE_DIR}/src)

# --- Component under test ---------------------------------------------------

set(DDK_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

set(DDK_SOURCES
    ${DDK_ROOT}/src/session/Session.cpp
    ${DDK_ROOT}/src/transport/ApduCommand.cpp
    ${DDK_ROOT}/src/transport/NfcChannel.cpp
    ${DDK_ROOT}/src/transport/BleMessages.cpp
    ${DDK_ROOT}/src/transport/BleMessageSecurity.cpp
    ${DDK_ROOT}/src/transport/BleTransport.cpp
    ${DDK_ROOT}/src/transport/BleChannel.cpp
    ${DDK_ROOT}/src/crypto/CommonCryptoUtils.cpp
    ${DDK_ROOT}/src/crypto/GcmSecureChannel.cpp
    ${DDK_ROOT}/src/crypto/x963kdf.cpp
    ${DDK_ROOT}/src/aliro/Profile.cpp
    ${DDK_ROOT}/src/aliro/BleProfile.cpp
    ${DDK_ROOT}/src/aliro/BleFlow.cpp
    ${DDK_ROOT}/src/aliro/BleAdvertising.cpp
    ${DDK_ROOT}/src/aliro/AliroKeySchedule.cpp
    ${DDK_ROOT}/src/aliro/AliroSecureContext.cpp
    ${DDK_ROOT}/src/aliro/AliroStepUp.cpp
    ${DDK_ROOT}/src/aliro/ProfileFactory.cpp
    ${DDK_ROOT}/src/auth/AliroFastAuth.cpp
    ${DDK_ROOT}/src/auth/AliroStdAuth.cpp
    ${DDK_ROOT}/src/utils/BerTlv.cpp
    ${DDK_ROOT}/src/utils/CoseSign1.cpp
    ${DDK_ROOT}/src/utils/ndef.cpp
)

add_library(ddk_under_test STATIC ${DDK_SOURCES})
target_include_directories(ddk_under_test PUBLIC
    ${DDK_ROOT}/include
    ${DDK_ROOT}/include/ddk
    ${tinycbor_SOURCE_DIR}/src)
target_include_directories(ddk_under_test PRIVATE ${DDK_ROOT}/priv)
target_link_libraries(ddk_under_test PUBLIC mbedcrypto sodium tinycbor)
add_dependencies(ddk_under_test libsodium)

# --- Shared flow-test harness (simulated Aliro endpoint) --------------------
# The BLE additions reuse the same endpoint: a loopback BleLink pair plus a
# simulated user device running the device side of the BLE flows on its own
# thread.

add_library(aliro_test_harness STATIC
    harness/aliro_test_endpoint.cpp
    harness/ble_loopback.cpp
    harness/aliro_ble_device.cpp)
target_include_directories(aliro_test_harness PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/harness
    ${DDK_ROOT}/priv)
target_link_libraries(aliro_test_harness PUBLIC ddk_under_test)

# --- Tests -------------------------------------------------------------------

enable_testing()

# Pre-existing plain-main tests, wired in as-is. They include private
# headers (ndef.h), so priv is needed too.
foreach(t IN ITEMS span_test ndef_pack_test ndef_unpack_test)
    add_executable(${t} ${t}.cpp)
    target_include_directories(${t} PRIVATE ${DDK_ROOT}/priv)
    target_link_libraries(${t} PRIVATE ddk_under_test)
    add_test(NAME ${t} COMMAND ${t})
endforeach()

# Catch2 tests — the Fast/Standard flow tests, the step-up parser unit
# tests, the full step-up flow, and the BLE transport/flow tests, all
# sharing the simulated-endpoint harness.
foreach(t IN ITEMS
        aliro_fast_flow_test
        aliro_standard_flow_test
        aliro_stepup_parser_test
        aliro_stepup_flow_test
        aliro_ble_message_test
        aliro_ble_advertising_test
        aliro_ble_security_test
        aliro_ble_flow_test
        aliro_uwb_flow_test)
    add_executable(${t} ${t}.cpp)
    target_link_libraries(${t} PRIVATE aliro_test_harness Catch2::Catch2WithMain)
    add_test(NAME ${t} COMMAND ${t})
endforeach()
