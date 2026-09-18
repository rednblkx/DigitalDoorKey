#pragma once

// Compatibility shim bridging mbedtls v3 (public legacy API, IDF <= 5.x) and
// mbedtls v4 / TF-PSA-Crypto (IDF 6.x)

#include <mbedtls/build_info.h>

#if MBEDTLS_VERSION_MAJOR >= 4
#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif
#include <mbedtls/private/sha256.h>
#include <mbedtls/private/sha1.h>
#include <mbedtls/private/aes.h>
#include <mbedtls/private/gcm.h>
#include <mbedtls/private/cmac.h>
#include <mbedtls/private/ecp.h>
#include <mbedtls/private/ecdsa.h>
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/cipher.h>
#include "mbedtls/md.h"        // tf-psa-crypto public header, still has md API
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "ddk_crypto_shims.h"  // mbedtls_hkdf + mbedtls_ecdh_compute_shared
#else
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/cmac.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/error.h>
#endif
