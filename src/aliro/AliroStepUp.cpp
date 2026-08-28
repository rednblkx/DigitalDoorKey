#include "aliro/AliroStepUp.h"
#include "aliro/AliroSecureContext.h"
#include "CoseSign1.h"
#include "BerTlv.h"
#include "CommonCryptoUtils.h"
#include "DDKLogging.h"
#include "ddk/store/CredentialStore.h"
#include <cbor.h>
#include <cstring>
#include "ddk/store/Issuer.h"

namespace {
constexpr const char* TAG = "AliroStepUp";
constexpr const char* kAccessDocType = "aliro-a";
constexpr const char* kRevocationDocType = "aliro-r";
constexpr uint8_t kStepUpAid[] = {0xA0,0x00,0x00,0x09,0x09,0xAC,0xCE,0x55,0x02};
} // namespace

AliroStepUp::AliroStepUp(ddk::Session& session, AliroSecureContext& ctx)
    : session_(session), ctx_(ctx) {}

void AliroStepUp::selectStepUpAid()
{
    // SELECT: CLA=0x00, INS=0xA4, P1=0x04, P2=0x00, AID
    std::vector<uint8_t> apdu{0x00, 0xA4, 0x04, 0x00,
                               static_cast<uint8_t>(sizeof(kStepUpAid))};
    apdu.insert(apdu.end(), std::begin(kStepUpAid), std::end(kStepUpAid));
    apdu.push_back(0x00);  // Le
    auto resp = session_.apdu().transceive(apdu);
    if(!resp.ok())  LOG(D, "Step-up AID SELECT failed");
}

std::vector<uint8_t> AliroStepUp::buildDeviceRequest(
    const std::vector<std::string>& doc_types,
    const std::map<std::string, bool>& scopes)
{
    // {"1": version, "2": [ {"1": tag24( {"1": {docType: scopes}, "5": docType} )} ]}
    uint8_t buf[1024];
    CborEncoder root, rootMap, docArray;

    cbor_encoder_init(&root, buf, sizeof(buf), 0);
    cbor_encoder_create_map(&root, &rootMap, 2);
    cbor_encode_text_stringz(&rootMap, "1");          // version
    cbor_encode_text_stringz(&rootMap, "1.0");
    cbor_encode_text_stringz(&rootMap, "2");          // docRequests
    cbor_encoder_create_array(&rootMap, &docArray, doc_types.size());

    for (const auto& doc_type : doc_types) {
        // Inner ItemsRequest: {"1": {docType: scopes}, "5": docType}
        uint8_t inner[512];
        CborEncoder ienc, imap, nsMap, scopeMap;
        cbor_encoder_init(&ienc, inner, sizeof(inner), 0);
        cbor_encoder_create_map(&ienc, &imap, 2);
        cbor_encode_text_stringz(&imap, "1");         // nameSpaces
        cbor_encoder_create_map(&imap, &nsMap, 1);
        cbor_encode_text_string(&imap, doc_type.c_str(), doc_type.size());
        cbor_encoder_create_map(&imap, &scopeMap, scopes.size());
        for (const auto& [element, retain] : scopes) {
            cbor_encode_text_string(&scopeMap, element.c_str(), element.size());
            cbor_encode_boolean(&scopeMap, retain);
        }
        cbor_encoder_close_container(&imap, &nsMap);
        cbor_encode_text_stringz(&imap, "5");         // docType
        cbor_encode_text_string(&imap, doc_type.c_str(), doc_type.size());
        cbor_encoder_close_container(&ienc, &imap);
        size_t inner_len = cbor_encoder_get_buffer_size(&ienc, inner);

        // DocRequest: {"1": tag24(inner)}
        CborEncoder docReq;
        cbor_encoder_create_map(&docArray, &docReq, 1);
        cbor_encode_text_stringz(&docReq, "1");       // itemsRequest
        cbor_encode_tag(&docReq, CborEncodedCborTag);
        cbor_encode_byte_string(&docReq, inner, inner_len);
        cbor_encoder_close_container(&docArray, &docReq);
    }
    cbor_encoder_close_container(&rootMap, &docArray);
    cbor_encoder_close_container(&root, &rootMap);

    size_t len = cbor_encoder_get_buffer_size(&root, buf);
    return std::vector<uint8_t>(buf, buf + len);
}

AliroStepUpResult AliroStepUp::parseDeviceResponse(ddk::span<const uint8_t> cbor)
{
    AliroStepUpResult result;
    CborParser parser;
    CborValue root, documents, document, issuer_signed, issuer_auth;

    if (cbor_parser_init(cbor.data(), cbor.size(), 0, &parser, &root)
        != CborNoError || !cbor_value_is_map(&root))
        return result;

    // "2" = documents
    if (cbor_value_map_find_value(&root, "2", &documents) != CborNoError ||
        !cbor_value_is_array(&documents))
        return result;

    if (cbor_value_enter_container(&documents, &document) != CborNoError)
        return result;

    while (!cbor_value_at_end(&document)) {
        if (!cbor_value_is_map(&document)) break;

        // "1" = issuerSigned
        if (cbor_value_map_find_value(&document, "1", &issuer_signed)
            == CborNoError && cbor_value_is_map(&issuer_signed))
        {
            // "2" = issuerAuth (COSE Sign1 array)
            if (cbor_value_map_find_value(&issuer_signed, "2", &issuer_auth)
                == CborNoError && cbor_value_is_array(&issuer_auth))
            {
                auto cose = CoseSign1::parse_from_iterator(&issuer_auth);
                if (!cose) { LOG(E, "CoseSign1 parse failed"); break; }

                // Match issuer by COSE header key 4 (issuer_id)
                ddk::Issuer* found = nullptr;
                if (cose->issuer_id && cose->issuer_id->size() == 8) {
                    for (auto& iss : session_.store().issuers()) {
                        if (iss.id.size() == 8 &&
                            CommonCryptoUtils::constant_time_compare(
                                iss.id, *cose->issuer_id)) {
                            found = &iss; break;
                        }
                    }
                }
                if (!found) { LOG(E, "No matching issuer"); break; }

                // Extract deviceKey from MSO (tag-24 payload)
                std::vector<uint8_t> x, y;
                if (!extractDeviceKey(cose->payload, x, y) ||
                    x.size() != 32 || y.size() != 32) {
                    LOG(E, "deviceKey extraction failed"); break;
                }

                // Verify: ES256 (Aliro issuerAuth — NOT Ed25519)
                if (!CoseSign1::verify(*cose, CoseAlgorithm::ES256,
                                       found->public_key)) {
                    LOG(E, "ES256 verification failed"); break;
                }

                result.issuer = found;
                result.endpoint_public_key.push_back(0x04);
                result.endpoint_public_key.insert(
                    result.endpoint_public_key.end(), x.begin(), x.end());
                result.endpoint_public_key.insert(
                    result.endpoint_public_key.end(), y.begin(), y.end());
                result.documents.push_back(cose->payload);
                result.success = true;
            }
        }
        cbor_value_advance(&document);
    }
    return result;
}

bool AliroStepUp::extractDeviceKey(ddk::span<const uint8_t> payload,
                                    std::vector<uint8_t>& x_out,
                                    std::vector<uint8_t>& y_out)
{
    // payload = tag24(bstr) → MSO map
    CborParser parser; CborValue it;
    if (cbor_parser_init(payload.data(), payload.size(), 0, &parser, &it)
        != CborNoError || !cbor_value_is_tag(&it))
        return false;
    CborTag tag;
    cbor_value_get_tag(&it, &tag);
    if (tag != 24 || cbor_value_advance(&it) != CborNoError) return false;
    if (!cbor_value_is_byte_string(&it)) return false;

    std::vector<uint8_t> mso;
    size_t len = 0;
    cbor_value_get_string_length(&it, &len);
    mso.resize(len);
    cbor_value_copy_byte_string(&it, mso.data(), &len, nullptr);

    CborParser mso_parser; CborValue root;
    if (cbor_parser_init(mso.data(), mso.size(), 0, &mso_parser, &root)
        != CborNoError || !cbor_value_is_map(&root))
        return false;

    // Find deviceKeyInfo: text key "deviceKeyInfo" OR integer key 4.
    // Then deviceKey inside: text "deviceKey" OR integer 1.
    // Then COSE EC2 map: -2 = x, -3 = y.
    CborValue key_info;
    bool found_ki = false;
    if (cbor_value_map_find_value(&root, "deviceKeyInfo", &key_info)
        == CborNoError && cbor_value_is_map(&key_info)) {
        found_ki = true;
    } else {
        // Integer-key form: walk MSO map looking for key 4
        CborValue walk;
        if (cbor_value_enter_container(&root, &walk) == CborNoError) {
            while (!cbor_value_at_end(&walk)) {
                if (cbor_value_is_integer(&walk)) {
                    int64_t k; cbor_value_get_int64(&walk, &k);
                    if (cbor_value_advance(&walk) == CborNoError) {
                        if (k == 4 && cbor_value_is_map(&walk)) {
                            key_info = walk; found_ki = true; break;
                        }
                    }
                }
                if (cbor_value_at_end(&walk)) break;
                cbor_value_advance(&walk);
            }
        }
    }
    if (!found_ki) return false;

    // Find deviceKey: "deviceKey" or integer 1
    CborValue key_map;
    bool found_dk = false;
    if (cbor_value_map_find_value(&key_info, "deviceKey", &key_map)
        == CborNoError && cbor_value_is_map(&key_map)) {
        found_dk = true;
    } else {
        CborValue walk;
        if (cbor_value_enter_container(&key_info, &walk) == CborNoError) {
            while (!cbor_value_at_end(&walk)) {
                if (cbor_value_is_integer(&walk)) {
                    int64_t k; cbor_value_get_int64(&walk, &k);
                    if (cbor_value_advance(&walk) == CborNoError) {
                        if (k == 1 && cbor_value_is_map(&walk)) {
                            key_map = walk; found_dk = true; break;
                        }
                    }
                }
                if (cbor_value_at_end(&walk)) break;
                cbor_value_advance(&walk);
            }
        }
    }
    if (!found_dk) return false;

    // COSE EC2 map: -2 = x (bstr 32), -3 = y (bstr 32)
    CborValue kv;
    if (cbor_value_enter_container(&key_map, &kv) != CborNoError) return false;
    while (!cbor_value_at_end(&kv)) {
        if (cbor_value_is_integer(&kv)) {
            int64_t k; cbor_value_get_int64(&kv, &k);
            if (cbor_value_advance(&kv) != CborNoError) return false;
            if ((k == -2 || k == -3) && cbor_value_is_byte_string(&kv)) {
                size_t l = 0;
                cbor_value_get_string_length(&kv, &l);
                auto& out = (k == -2) ? x_out : y_out;
                out.resize(l);
                cbor_value_copy_byte_string(&kv, out.data(), &l, nullptr);
            }
        }
        if (cbor_value_at_end(&kv)) break;
        if (cbor_value_advance(&kv) != CborNoError) return false;
    }
    return !x_out.empty() && !y_out.empty();
}

AliroStepUpResult AliroStepUp::run(
    ddk::aliro::SignalingBitmask signaling_bitmap,
    const std::map<std::string, bool>& scopes)
{
    std::vector<std::string> doc_types;
    if (has(signaling_bitmap, ddk::aliro::SignalingBitmask::AccessDocumentRetrievable))
        doc_types.push_back(kAccessDocType);
    if (has(signaling_bitmap, ddk::aliro::SignalingBitmask::RevocationDocumentRetrievable))
        doc_types.push_back(kRevocationDocType);
    if (doc_types.empty()) {
        LOG(W, "Step-up: signaling bitmap indicates no retrievable documents");
        return {};
    }

    if (has(signaling_bitmap, ddk::aliro::SignalingBitmask::StepUpSelectRequired))
        selectStepUpAid();

    auto request = buildDeviceRequest(doc_types, scopes);

    // Encrypt + SessionData wrap + 0x53 TLV + ENVELOPE + decrypt —
    auto plaintext = ctx_.envelope(session_, request);
    if (!plaintext || plaintext->empty()) {
        LOG(E, "Step-up: ENVELOPE response decrypt failed");
        return {};
    }

    return parseDeviceResponse(*plaintext);
}
