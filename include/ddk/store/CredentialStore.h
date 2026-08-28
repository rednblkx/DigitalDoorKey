#pragma once
#include "ddk/Span.h"
#include <cstdint>

namespace ddk {

class Issuer;
class Endpoint;
class ReaderIdentity;

class CredentialStore {
public:
    virtual ~CredentialStore() = default;
    virtual const ReaderIdentity& reader_identity() const = 0;
    virtual void provision_identity(const ReaderIdentity&) = 0;
    virtual span<Issuer> issuers() = 0;
    virtual void save() = 0;
};

// Free helpers — used by firmware provisioning glue now,
// by StandardAuth's identity lookups after profile extraction.
Issuer*  find_issuer_by_id(span<Issuer>, span<const uint8_t> id);
Endpoint* find_endpoint_by_id(span<Issuer>, span<const uint8_t> id);
Endpoint* find_endpoint_by_public_key(span<Issuer>, span<const uint8_t> pk);
}
