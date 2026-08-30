#include "aliro_test_endpoint.hpp"

#include "aliro/AliroKeySchedule.h"
#include "aliro/Profile.h"
#include "CommonCryptoUtils.h"
#include "CoseSign1.h"
#include "BerTlv.h"
#include "TLV8.hpp"
#include "simple_tlv.hpp"
#include "x963kdf.h"
#include "ddk/aliro/ProfileFactory.h"
#include "ddk/session/AuthOutcome.h"

#include <cbor.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>

namespace aliro_test {

std::vector<uint8_t> aliro_gcm(const std::array<uint8_t, 32>& key,
                               uint8_t direction_last_byte, uint32_t counter,
                               const std::vector<uint8_t>& in, bool encrypt)
{
    std::array<uint8_t, 12> iv{};
    iv[7] = direction_last_byte;
    iv[8]  = static_cast<uint8_t>(counter >> 24);
    iv[9]  = static_cast<uint8_t>(counter >> 16);
    iv[10] = static_cast<uint8_t>(counter >> 8);
    iv[11] = static_cast<uint8_t>(counter);
    return encrypt ? CommonCryptoUtils::encryptAesGcm(in, key, iv)
                   : CommonCryptoUtils::decryptAesGcm(in, key, iv);
}

std::vector<uint8_t> session_data_wrap(const std::vector<uint8_t>& ct)
{
    uint8_t buf[4096];
    CborEncoder enc, map;
    cbor_encoder_init(&enc, buf, sizeof(buf), 0);
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_text_stringz(&map, "data");
    cbor_encode_byte_string(&map, ct.data(), ct.size());
    cbor_encoder_close_container(&enc, &map);
    size_t n = cbor_encoder_get_buffer_size(&enc, buf);
    return std::vector<uint8_t>(buf, buf + n);
}

std::vector<uint8_t> session_data_unwrap(const std::vector<uint8_t>& cbor)
{
    CborParser parser; CborValue it, val;
    if (cbor_parser_init(cbor.data(), cbor.size(), 0, &parser, &it) != CborNoError ||
        !cbor_value_is_map(&it) ||
        cbor_value_map_find_value(&it, "data", &val) != CborNoError ||
        !cbor_value_is_byte_string(&val))
        return {};
    size_t len = 0;
    if (cbor_value_get_string_length(&val, &len) != CborNoError) return {};
    std::vector<uint8_t> out(len);
    if (len && cbor_value_copy_byte_string(&val, out.data(), &len, nullptr) != CborNoError)
        return {};
    return out;
}

std::vector<uint8_t> tlv53(const std::vector<uint8_t>& value)
{
    std::vector<uint8_t> out{0x53};
    if (value.size() < 0x80) {
        out.push_back(static_cast<uint8_t>(value.size()));
    } else {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(value.size()));
    }
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

namespace {

// SHA-256 + ECDSA-P256, raw 32B-left-padded r||s — the encoding
// AliroStdAuth verifies against the store endpoint's public key.
std::vector<uint8_t> sign_es256_raw(const std::array<uint8_t, 32>& priv,
                                    const std::vector<uint8_t>& message)
{
    std::vector<uint8_t> sig(64, 0);
    uint8_t hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               message.data(), message.size(), hash);

    CommonCryptoUtils::EcpGroupGuard grp;
    CommonCryptoUtils::MpiGuard d, r, s;
    mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
    if (mbedtls_mpi_read_binary(d, priv.data(), priv.size()) != 0) return {};
    if (mbedtls_ecdsa_sign(grp, r, s, d, hash, sizeof(hash),
                           CommonCryptoUtils::esp_rng, nullptr) != 0) return {};

    size_t r_size = mbedtls_mpi_size(r);
    size_t s_size = mbedtls_mpi_size(s);
    if (r_size > 32 || s_size > 32) return {};
    mbedtls_mpi_write_binary(r, sig.data() + (32 - r_size), r_size);
    mbedtls_mpi_write_binary(s, sig.data() + 32 + (32 - s_size), s_size);
    return sig;
}

struct SimpleTlvField {
    uint8_t tag;
    std::vector<uint8_t> value;
};

// Command-side simple TLV walk (tag, 1B length or 0x81-prefixed, value).
std::vector<SimpleTlvField> parse_simple_tlvs(const std::vector<uint8_t>& buf)
{
    std::vector<SimpleTlvField> out;
    size_t i = 0;
    while (i + 2 <= buf.size()) {
        const uint8_t tag = buf[i];
        size_t hdr = 2;
        size_t len = buf[i + 1];
        if (len == 0x81) {
            if (i + 3 > buf.size()) break;
            len = buf[i + 2];
            hdr = 3;
        }
        if (i + hdr + len > buf.size()) break;
        out.push_back({tag, std::vector<uint8_t>(
            buf.begin() + static_cast<long>(i + hdr),
            buf.begin() + static_cast<long>(i + hdr + len))});
        i += hdr + len;
    }
    return out;
}

}  // namespace

P256KeyPair generate_p256_key()
{
    auto [priv, pub] = CommonCryptoUtils::generateEphemeralKey();
    P256KeyPair out;
    std::copy_n(pub.begin(), out.pub.size(), out.pub.begin());
    std::copy_n(pub.begin() + 1, out.pub_x.size(), out.pub_x.begin());
    // The scalar may come back shorter than 32 bytes (minimal mbedtls_mpi
    // encoding) — left-pad it into the fixed-size array.
    std::fill(out.priv.begin(), out.priv.end(), 0);
    if (priv.size() <= out.priv.size())
        std::copy(priv.begin(), priv.end(), out.priv.end() - priv.size());
    return out;
}

std::vector<uint8_t> build_select_fci()
{
    return {0x6F, 0x06, 0xA5, 0x04, 0x5C, 0x02, 0x01, 0x00};
}

std::vector<uint8_t> fci_proprietary()
{
    return {0xA5, 0x04, 0x5C, 0x02, 0x01, 0x00};
}

std::vector<uint8_t> test_key_slot() { return {1, 2, 3, 4, 5, 6, 7, 8}; }

std::vector<uint8_t> credential_tdate()
{
    std::vector<uint8_t> v(20);
    for (size_t i = 0; i < v.size(); ++i) v[i] = static_cast<uint8_t>(0x30 + i);
    return v;
}

std::vector<uint8_t> revocation_tdate()
{
    std::vector<uint8_t> v(20);
    for (size_t i = 0; i < v.size(); ++i) v[i] = static_cast<uint8_t>(0x40 + i);
    return v;
}

std::vector<uint8_t> mock_device_request()
{
    return {
        0xa2, 0x61, 0x31, 0x63, 0x31, 0x2e, 0x30, 0x61, 0x32, 0x81, 0xa1, 0x61,
        0x31, 0xd8, 0x18, 0x58, 0x20, 0xa2, 0x61, 0x31, 0xa1, 0x67, 0x61, 0x6c,
        0x69, 0x72, 0x6f, 0x2d, 0x61, 0xa1, 0x67, 0x6d, 0x61, 0x74, 0x74, 0x65,
        0x72, 0x31, 0xf5, 0x61, 0x35, 0x67, 0x61, 0x6c, 0x69, 0x72, 0x6f, 0x2d,
        0x61,
    };
}

namespace {

// COSE_Sign1 protected headers: {1: -7} (ES256), embedded as a bstr.
std::vector<uint8_t> cose_es256_protected_headers()
{
    uint8_t ph[16];
    CborEncoder e, ph_map;
    cbor_encoder_init(&e, ph, sizeof(ph), 0);
    cbor_encoder_create_map(&e, &ph_map, 1);
    cbor_encode_int(&ph_map, 1);
    cbor_encode_int(&ph_map, -7);
    cbor_encoder_close_container(&e, &ph_map);
    size_t ph_len = cbor_encoder_get_buffer_size(&e, ph);
    return std::vector<uint8_t>(ph, ph + ph_len);
}

// issuerAuth = [bstr(protected), {4: bstr(issuer_id)}, bstr(payload), bstr(sig)]
// encoded inline (COSE_Sign1 is an array, not a bstr).
void encode_issuer_auth(CborEncoder* parent, const StepUpMaterial& m)
{
    CborEncoder arr, unprot;
    cbor_encoder_create_array(parent, &arr, 4);
    cbor_encode_byte_string(&arr, m.protected_headers.data(),
                            m.protected_headers.size());
    cbor_encoder_create_map(&arr, &unprot, 1);
    cbor_encode_int(&unprot, 4);  // issuer id (key identifier)
    cbor_encode_byte_string(&unprot, m.issuer_id.data(), m.issuer_id.size());
    cbor_encoder_close_container(&arr, &unprot);
    cbor_encode_byte_string(&arr, m.payload.data(), m.payload.size());
    cbor_encode_byte_string(&arr, m.sig.data(), m.sig.size());
    cbor_encoder_close_container(parent, &arr);
}

}  // namespace

StepUpMaterial make_step_up_material(const std::array<uint8_t, 32>& device_x,
                                     const std::array<uint8_t, 32>& device_y,
                                     const std::vector<uint8_t>& issuer_id,
                                     bool mso_text_keys, bool omit_tag24)
{
    StepUpMaterial m;
    m.x.assign(device_x.begin(), device_x.end());
    m.y.assign(device_y.begin(), device_y.end());
    m.issuer_id = issuer_id;

    // MSO {4: {1: {1: 2, -1: 1, -2: x, -3: y}}, 5: "aliro-a"} — MSO keys as
    // ISO integers or digit text strings (mso_text_keys, the real-device
    // form); COSE labels stay integers.
    auto enc_mso_key = [mso_text_keys](CborEncoder* e, int64_t k) {
        if (mso_text_keys) {
            char b[8];
            std::snprintf(b, sizeof(b), "%lld", static_cast<long long>(k));
            cbor_encode_text_stringz(e, b);
        } else {
            cbor_encode_int(e, k);
        }
    };

    uint8_t mso_buf[256];
    CborEncoder e, mso_map, ki_map, key_map;
    cbor_encoder_init(&e, mso_buf, sizeof(mso_buf), 0);
    cbor_encoder_create_map(&e, &mso_map, 2);
    enc_mso_key(&mso_map, 4);  // deviceKeyInfo
    cbor_encoder_create_map(&mso_map, &ki_map, 1);
    enc_mso_key(&ki_map, 1);   // deviceKey
    cbor_encoder_create_map(&ki_map, &key_map, 4);
    cbor_encode_int(&key_map, 1);  cbor_encode_int(&key_map, 2);   // kty: EC2
    cbor_encode_int(&key_map, -1); cbor_encode_int(&key_map, 1);   // crv: P-256
    cbor_encode_int(&key_map, -2);
    cbor_encode_byte_string(&key_map, m.x.data(), m.x.size());
    cbor_encode_int(&key_map, -3);
    cbor_encode_byte_string(&key_map, m.y.data(), m.y.size());
    cbor_encoder_close_container(&ki_map, &key_map);
    cbor_encoder_close_container(&mso_map, &ki_map);
    enc_mso_key(&mso_map, 5);
    cbor_encode_text_stringz(&mso_map, "aliro-a");
    cbor_encoder_close_container(&e, &mso_map);
    size_t mso_len = cbor_encoder_get_buffer_size(&e, mso_buf);

    // payload = tag24(MSO), or the MSO map encoding directly when the tag is
    // omitted (the lenient form extractDeviceKey accepts).
    uint8_t payload_buf[300];
    cbor_encoder_init(&e, payload_buf, sizeof(payload_buf), 0);
    if (!omit_tag24) {
        cbor_encode_tag(&e, 24);
        cbor_encode_byte_string(&e, mso_buf, mso_len);
    } else {
        cbor_encode_byte_string(&e, mso_buf, mso_len);
    }
    size_t payload_len = cbor_encoder_get_buffer_size(&e, payload_buf);
    m.payload.assign(payload_buf, payload_buf + payload_len);
    m.protected_headers = cose_es256_protected_headers();
    return m;
}

std::vector<uint8_t> sign_cose_es256(const P256KeyPair& key,
                                     const std::vector<uint8_t>& protected_headers,
                                     const std::vector<uint8_t>& payload)
{
    auto sig_struct = CoseSign1::build_sig_structure(protected_headers, {}, payload);

    uint8_t hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               sig_struct.data(), sig_struct.size(), hash);

    CommonCryptoUtils::EcpGroupGuard grp;
    CommonCryptoUtils::MpiGuard d, r, s;
    mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_mpi_read_binary(d, key.priv.data(), key.priv.size());
    if (mbedtls_ecdsa_sign(grp, r, s, d, hash, sizeof(hash),
                           CommonCryptoUtils::esp_rng, nullptr) != 0)
        return {};

    std::vector<uint8_t> sig(64, 0);
    size_t r_size = mbedtls_mpi_size(r);
    size_t s_size = mbedtls_mpi_size(s);
    if (r_size > 32 || s_size > 32) return {};
    mbedtls_mpi_write_binary(r, sig.data() + (32 - r_size), r_size);
    mbedtls_mpi_write_binary(s, sig.data() + 32 + (32 - s_size), s_size);
    return sig;
}

// DeviceResponse {1: "1.0", 2: [doc], 3: 0} with the doc map embedded inline.
std::vector<uint8_t> build_step_up_device_response(const StepUpMaterial& m,
                                                   bool text_keys,
                                                   std::vector<uint8_t>* doc_out)
{
    auto encode = [&](CborEncoder* parent, bool text) {
        // Document: {1: {2: issuerAuth}, 5: docType}
        CborEncoder doc_map, is_map;
        cbor_encoder_create_map(parent, &doc_map, 2);
        text ? cbor_encode_text_stringz(&doc_map, "1")
             : cbor_encode_int(&doc_map, 1);  // issuerSigned
        cbor_encoder_create_map(&doc_map, &is_map, 1);
        text ? cbor_encode_text_stringz(&is_map, "2")
             : cbor_encode_int(&is_map, 2);   // issuerAuth (COSE_Sign1, inline)
        encode_issuer_auth(&is_map, m);
        cbor_encoder_close_container(&doc_map, &is_map);
        text ? cbor_encode_text_stringz(&doc_map, "5")
             : cbor_encode_int(&doc_map, 5);
        cbor_encode_text_stringz(&doc_map, "aliro-a");
        cbor_encoder_close_container(parent, &doc_map);
    };

    // Standalone doc encoding (expected slice content)
    uint8_t doc_buf[768];
    CborEncoder e;
    cbor_encoder_init(&e, doc_buf, sizeof(doc_buf), 0);
    encode(&e, text_keys);
    size_t doc_len = cbor_encoder_get_buffer_size(&e, doc_buf);
    std::vector<uint8_t> doc(doc_buf, doc_buf + doc_len);
    if (doc_out) *doc_out = doc;

    // Response with the doc map nested inline
    uint8_t resp_buf[1024];
    CborEncoder resp, resp_map, docs_arr;
    cbor_encoder_init(&resp, resp_buf, sizeof(resp_buf), 0);
    cbor_encoder_create_map(&resp, &resp_map, 3);
    text_keys ? cbor_encode_text_stringz(&resp_map, "1")
              : cbor_encode_int(&resp_map, 1);
    cbor_encode_text_stringz(&resp_map, "1.0");
    text_keys ? cbor_encode_text_stringz(&resp_map, "2")
              : cbor_encode_int(&resp_map, 2);
    cbor_encoder_create_array(&resp_map, &docs_arr, 1);
    encode(&docs_arr, text_keys);
    cbor_encoder_close_container(&resp_map, &docs_arr);
    text_keys ? cbor_encode_text_stringz(&resp_map, "3")
              : cbor_encode_int(&resp_map, 3);
    cbor_encode_int(&resp_map, 0);  // status OK
    cbor_encoder_close_container(&resp, &resp_map);
    size_t resp_len = cbor_encoder_get_buffer_size(&resp, resp_buf);
    return std::vector<uint8_t>(resp_buf, resp_buf + resp_len);
}

FakeStore::FakeStore()
{
    identity.group_identifier.resize(16);
    identity.sub_identifier.resize(16);
    for (size_t i = 0; i < 16; ++i) {
        identity.group_identifier[i] = static_cast<uint8_t>(0xA0 + i);
        identity.sub_identifier[i] = static_cast<uint8_t>(0xB0 + i);
    }
}

ddk::NfcChannel::Callback AliroTestEndpoint::callback()
{
    return [this](std::vector<uint8_t>& command, std::vector<uint8_t>& response) {
        if (command.size() < 5) return false;
        const uint8_t cla = command[0];
        const uint8_t ins = command[1];
        apdus_seen.emplace_back(cla, ins);
        // Lc-aware: take exactly Lc data bytes, so a case-4 trailing Le
        // (the phone-side framing) never leaks into the parsed payload.
        const size_t lc = command[4];
        if (command.size() < 5 + lc) return false;
        std::vector<uint8_t> data(command.begin() + 5,
                                  command.begin() + 5 + lc);

        ddk::ApduResponse r;
        switch (ins) {
            case 0xA4: r = handle_select(data); break;
            case 0x80: r = handle_auth0(data); break;
            case 0x81: r = handle_auth1(data); break;
            case 0xC9: r = handle_exchange(data); break;
            case 0x3C: r = handle_control_flow(data); break;
            case 0xC3: r = handle_envelope(data); break;
            default:   r = {{}, 0x6D, 0x00}; break;
        }
        response = std::move(r.data);
        response.push_back(r.sw1);
        response.push_back(r.sw2);
        return true;
    };
}

ddk::ApduResponse AliroTestEndpoint::handle_select(const std::vector<uint8_t>& data)
{
    // Distinguish the expedited-phase AID (...01) from the step-up AID
    // (...02). Both get a minimal FCI + 9000.
    constexpr std::array<uint8_t, 9> kStepUpAid{0xA0, 0x00, 0x00, 0x09, 0x09,
                                                0xAC, 0xCE, 0x55, 0x02};
    if (data.size() >= kStepUpAid.size() &&
        std::equal(kStepUpAid.begin(), kStepUpAid.end(), data.begin()))
        ++step_up_selects;

    auto fci = build_select_fci();
    return {std::move(fci), 0x90, 0x00};
}

AliroKeySchedule::SessionInput AliroTestEndpoint::session_input(
    const std::vector<uint8_t>& fci) const
{
    AliroKeySchedule::SessionInput in;
    in.reader_pk_x = reader_pk_x;
    in.reader_identifier = reader_identifier;
    in.reader_eph_x = ddk::span(reader_eph_pub.data() + 1, 32);
    in.endpoint_eph_x = ddk::span(endpoint_eph_pub.data() + 1, 32);
    in.transaction_id = txn_id;
    in.version = version;
    in.flags = flags;
    in.fci_proprietary = fci;
    in.interface = static_cast<uint8_t>(interface_kind);
    in.auth0_info_suffix = {};
    return in;
}

ddk::ApduResponse AliroTestEndpoint::handle_auth0(const std::vector<uint8_t>& data)
{
    auto fields = parse_simple_tlvs(data);
    auto get = [&](uint8_t tag) -> const std::vector<uint8_t>* {
        auto it = std::find_if(fields.begin(), fields.end(),
                               [tag](const SimpleTlvField& f) { return f.tag == tag; });
        return it == fields.end() ? nullptr : &it->value;
    };

    if (const auto* v = get(0x87); v && v->size() == 65)
        std::copy_n(v->begin(), 65, reader_eph_pub.begin());
    if (const auto* v = get(0x4C))
        std::copy_n(v->begin(), std::min(txn_id.size(), v->size()), txn_id.begin());
    if (const auto* v = get(0x4D)) reader_identifier = *v;
    if (const auto* v = get(0x41); v && !v->empty()) flags[0] = (*v)[0];
    if (const auto* v = get(0x42); v && !v->empty()) flags[1] = (*v)[0];
    if (const auto* v = get(0x5C); v && v->size() >= 2)
        version = {(*v)[0], (*v)[1]};

    auto eph = generate_p256_key();
    endpoint_eph_priv = eph.priv;
    endpoint_eph_pub = eph.pub;

    ddk::ApduResponse resp;
    resp.sw1 = 0x90;
    resp.sw2 = 0x00;
    TLV8 out;

    if (scenario.malformed_auth0) {
        // Cryptogram-shaped but no 0x86 pubkey: the reader must bail via
        // CONTROL FLOW instead of attempting either flow.
        out.add(0x9D, std::vector<uint8_t>(64, 0x5A));
        resp.data = out.get();
        return resp;
    }

    out.add(0x86, std::vector<uint8_t>(eph.pub.begin(), eph.pub.end()));

    if (scenario.serve_cryptogram && !persistent_key.empty()) {
        auto fci = fci_proprietary();
        AliroKeySchedule schedule;
        auto fast = schedule.derive_fast(session_input(fci),
                                         endpoint_key.pub_x, persistent_key);
        fast_sk_reader = fast.exchange_sk_reader;
        fast_sk_device = fast.exchange_sk_device;
        fast_ble_sk = fast.ble_sk;
        fast_ursk = fast.uwb_ranging_sk;

        std::array<uint8_t, 32> sk = fast.cryptogram_sk;
        if (scenario.tamper_cryptogram) {
            for (size_t i = 0; i < sk.size(); ++i)
                sk[i] = static_cast<uint8_t>(0xE0 + i);
        }

        TLV8 payload;
        payload.add(0x5E, std::vector<uint8_t>{0x00, 0x01});
        payload.add(0x91, credential_tdate());
        payload.add(0x92, revocation_tdate());
        // Fast cryptogram: all-zero IV (reader direction, counter 0).
        out.add(0x9D, aliro_gcm(sk, 0x00, 0, payload.get(), true));
    }

    resp.data = out.get();
    return resp;
}

ddk::ApduResponse AliroTestEndpoint::handle_auth1(const std::vector<uint8_t>& data)
{
    (void)data;
    saw_auth1 = true;

    // ECDH(endpoint eph priv, reader eph pub) → X963KDF(SHA256, 32, txn) —
    // exactly what AliroStdAuth runs on the reader side.
    std::array<uint8_t, 32> shared{};
    CommonCryptoUtils::get_shared_key(endpoint_eph_priv, reader_eph_pub,
                                      shared.data(), shared.size());
    X963KDF kdf(MBEDTLS_MD_SHA256, 32, txn_id.data(), txn_id.size());
    std::array<uint8_t, 32> derived{};
    kdf.derive(shared.data(), shared.size(), derived.data());

    auto fci = fci_proprietary();
    AliroKeySchedule schedule;
    auto vol = schedule.derive_volatile(session_input(fci), derived);
    std_sk_reader = vol.exchange_sk_reader;
    std_sk_device = vol.exchange_sk_device;
    step_up_sk_reader = vol.step_up_sk_reader;
    step_up_sk_device = vol.step_up_sk_device;
    std_ble_sk = vol.ble_sk;
    std_ursk = vol.uwb_ranging_sk;
    derived_key = derived;
    recorded_fci = fci;

    // Device signature over the input AliroStdAuth::buildVerificationInput
    // rebuilds on the reader side.
    std::array<uint8_t, 32> endpoint_eph_x{}, reader_eph_x{};
    std::copy_n(endpoint_eph_pub.begin() + 1, 32, endpoint_eph_x.begin());
    std::copy_n(reader_eph_pub.begin() + 1, 32, reader_eph_x.begin());

    constexpr std::array<uint8_t, 4> kDeviceCtx{0x4e, 0x88, 0x7b, 0x4c};
    std::vector<uint8_t> ver;
    auto append = [&ver](std::vector<uint8_t> tlv) {
        ver.insert(ver.end(), tlv.begin(), tlv.end());
    };
    append(simple_tlv(0x4D, reader_identifier));
    append(simple_tlv(0x86, endpoint_eph_x));
    append(simple_tlv(0x87, reader_eph_x));
    append(simple_tlv(0x4C, txn_id));
    append(simple_tlv(0x93, kDeviceCtx));

    std::vector<uint8_t> sig = scenario.corrupt_device_signature
        ? std::vector<uint8_t>(64, 0xAB)
        : sign_es256_raw(endpoint_key.priv, ver);

    TLV8 payload;
    payload.add(0x9E, std::move(sig));
    payload.add(0x5A, scenario.unknown_endpoint_key
        ? std::vector<uint8_t>(65, 0x11)
        : std::vector<uint8_t>(endpoint_key.pub.begin(), endpoint_key.pub.end()));
    payload.add(0x5E, scenario.step_up_select_required
        ? std::vector<uint8_t>{0x00, 0x05}   // Bit0 access doc + Bit2 step-up select
        : std::vector<uint8_t>{0x00, 0x01}); // Bit0 access doc
    payload.add(0x4E, scenario.unknown_endpoint_key
        ? std::vector<uint8_t>(8, 0x22)
        : test_key_slot());
    payload.add(0x91, credential_tdate());
    payload.add(0x92, revocation_tdate());

    ddk::ApduResponse resp;
    resp.data = aliro_gcm(std_sk_device, 0x01, 1, payload.get(), true);
    resp.sw1 = 0x90;
    resp.sw2 = 0x00;
    return resp;
}

ddk::ApduResponse AliroTestEndpoint::handle_exchange(const std::vector<uint8_t>& data)
{
    // Reader→endpoint EXCHANGE: reader direction, per-channel counter.
    // Active channel follows the reader's AliroSecureContext: once ENVELOPE
    // ran, the completion EXCHANGE uses the step-up keys.
    std::vector<uint8_t> plaintext;
    if (step_up_engaged) {
        plaintext = aliro_gcm(step_up_sk_reader, 0x00, step_up_reader_ctr,
                              std::vector<uint8_t>(data), false);
        ++step_up_reader_ctr;
    } else {
        const auto& sk_reader = saw_auth1 ? std_sk_reader : fast_sk_reader;
        plaintext = aliro_gcm(sk_reader, 0x00, reader_ctr,
                              std::vector<uint8_t>(data), false);
        ++reader_ctr;
    }
    if (plaintext.empty()) return {{}, 0x6A, 0x80};

    completion_payload = std::move(plaintext);
    completion_exchanged = true;
    // Empty data + 9000: AliroSecureContext::exchange returns as-is and
    // Profile::complete() treats SW 9000 as delivered.
    return {{}, 0x90, 0x00};
}

ddk::ApduResponse AliroTestEndpoint::handle_control_flow(const std::vector<uint8_t>& data)
{
    // BER-TLV body: 41 01 <s1> 42 01 <s2>
    if (data.size() >= 6)
        control_flow_status = std::make_pair(data[2], data[5]);
    return {{}, 0x90, 0x00};
}

ddk::ApduResponse AliroTestEndpoint::handle_envelope(const std::vector<uint8_t>& data)
{
    ++envelope_count;
    // ENVELOPE switches the reader's active channel to step-up for the rest
    // of the transaction.
    step_up_engaged = true;

    ddk::ApduResponse resp;
    auto msg = BerTlvMessage::from_bytes(data);
    const BerTlv* tlv = msg.find(0x53);
    if (!tlv) { resp.sw1 = 0x6A; resp.sw2 = 0x80; return resp; }

    auto ciphertext = session_data_unwrap(tlv->value);
    // Reader→device: step-up SK reader side, READER_MODE, per-channel counter.
    auto request = aliro_gcm(step_up_sk_reader, 0x00, step_up_reader_ctr,
                             ciphertext, false);
    ++step_up_reader_ctr;
    if (request.empty()) { resp.sw1 = 0x6A; resp.sw2 = 0x80; return resp; }
    decrypted_device_request = request;

    if (!scenario.serve_step_up) { resp.sw1 = 0x6A; resp.sw2 = 0x80; return resp; }
    if (step_up_response_cbor.empty()) build_step_up_response();

    // Device→reader: step-up SK device side, ENDPOINT_MODE, counter.
    auto enc = aliro_gcm(step_up_sk_device, 0x01, step_up_endpoint_ctr,
                         step_up_response_cbor, true);
    ++step_up_endpoint_ctr;
    if (enc.empty()) { resp.sw1 = 0x6A; resp.sw2 = 0x80; return resp; }

    resp.data = tlv53(session_data_wrap(enc));
    resp.sw1 = 0x90;
    resp.sw2 = 0x00;
    return resp;
}

void AliroTestEndpoint::build_step_up_response()
{
    std::array<uint8_t, 32> device_x{}, device_y{};
    std::copy_n(device_key.pub.begin() + 1, 32, device_x.begin());
    std::copy_n(device_key.pub.begin() + 33, 32, device_y.begin());

    auto material = make_step_up_material(device_x, device_y, issuer_id);
    material.sig = scenario.corrupt_step_up_signature
        ? std::vector<uint8_t>(64, 0xAB)
        : sign_cose_es256(issuer_key, material.protected_headers, material.payload);

    step_up_response_cbor = build_step_up_device_response(
        material, /*text_keys=*/false, &served_document_cbor);
}

AliroKeySchedule::SessionInput AliroTestEndpoint::recorded_session_input() const
{
    return session_input(recorded_fci);
}

FlowRig::FlowRig(bool provision_persistent_key)
{
    reader_key = generate_p256_key();
    endpoint_key = generate_p256_key();
    issuer_key = generate_p256_key();

    store.identity.private_key.assign(reader_key.priv.begin(), reader_key.priv.end());
    store.identity.public_key.assign(reader_key.pub.begin(), reader_key.pub.end());
    store.identity.public_key_x.assign(reader_key.pub_x.begin(), reader_key.pub_x.end());

    endpoint.endpoint_key = endpoint_key;
    endpoint.reader_pk_x = reader_key.pub_x;
    endpoint.device_key = endpoint_key;
    endpoint.issuer_key = issuer_key;

    if (provision_persistent_key) {
        for (size_t i = 0; i < endpoint.persistent_key.size(); ++i)
            endpoint.persistent_key[i] = static_cast<uint8_t>(0xC0 + i);
    }

    ddk::Issuer issuer;
    issuer.id = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    endpoint.issuer_id = issuer.id;
    issuer.public_key.assign(issuer_key.pub.begin(), issuer_key.pub.end());
    ddk::Endpoint ep;
    ep.id = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    ep.public_key.assign(endpoint_key.pub.begin(), endpoint_key.pub.end());
    ep.public_key_x.assign(endpoint_key.pub_x.begin(), endpoint_key.pub_x.end());
    ep.persistent_key.assign(endpoint.persistent_key.begin(),
                             endpoint.persistent_key.end());
    issuer.endpoints.push_back(std::move(ep));
    store.issuer_list.push_back(std::move(issuer));

    channel = std::make_shared<ddk::NfcChannel>(endpoint.callback());
}

ddk::AuthOutcome FlowRig::run(ddk::SessionConfig config)
{
    auto profile = ddk::aliro::make_profile();
    ddk::Session session(channel, store, std::move(config));

    // Expedited-phase SELECT, mirroring the production driver in
    // main/lock/aliro_door_lock_delegate.cpp::runAliroTransaction().
    std::vector<uint8_t> select_cmd{0x00, 0xA4, 0x04, 0x00, 0x09,
                                    0xA0, 0x00, 0x00, 0x09, 0x09,
                                    0xAC, 0xCE, 0x55, 0x01};
    auto sel = session.apdu().transceive(select_cmd);
    if (!sel.ok()) {
        ddk::AuthOutcome failed;
        failed.state = ddk::FlowState::Failed;
        failed.reason = ddk::FailureReason::ChannelError;
        return failed;
    }

    auto reason = profile->validate_select(session, sel.data);
    if (reason != ddk::FailureReason::None) {
        ddk::AuthOutcome failed;
        failed.state = ddk::FlowState::Failed;
        failed.reason = reason;
        return failed;
    }

    auto state = ddk::FlowState::Selected;
    while (state != ddk::FlowState::Done && state != ddk::FlowState::Failed)
        state = profile->step(session, state);

    auto outcome = profile->finalize(session);
    // AuthOutcome::access_document_cbor spans into Profile-owned state;
    // copy it while the profile is still alive.
    access_document.assign(outcome.access_document_cbor.begin(),
                           outcome.access_document_cbor.end());
    return outcome;
}

}  // namespace aliro_test
