#pragma once

#include <cstdint>
#include <vector>

typedef enum {
  kAliro = 0x00,
  kHomeKey = 0x01
} DigitalKeyType;

typedef enum
{
  kEndpoint_Public_Key = 0x86,
  kAuth0_Cryptogram = 0x9D,
  kAuth0Status = 0x90
} AUTH0_RESPONSE;

typedef enum
{
  kNDEF_MESSAGE = 0x53,
  kEnv1Status = 0x90
} ENVELOPE_RESPONSE;

typedef enum
{
  kCmdFlowFailed = 0x0,
  kCmdFlowSuccess = 0x01,
  kCmdFlowAttestation = 0x40
} CommandFlowStatus;

typedef enum
{
  kTransactionSTANDARD = 0x0,
  kTransactionFAST = 0x01
} KeyTransactionFlags;

typedef enum
{
  kFlowFAST = 0x00,
  kFlowSTANDARD = 0x01,
  kFlowATTESTATION = 0x02,
  kFlowNext = 0xFF,
  kFlowFailed = -1
} KeyFlow;

// struct hkEnrollment_t
// {
//   std::time_t unixTime = 0;
//   std::vector<uint8_t> payload;
// };
// struct hkEnrollments_t
// {
//   hkEnrollment_t hap;
//   hkEnrollment_t attestation;
// };

struct hkEndpoint_t
{
  std::vector<uint8_t> endpoint_id;
  uint32_t last_used_at = 0;
  uint8_t counter = 0;
  uint8_t key_type = 0;
  std::vector<uint8_t> endpoint_pk;
  std::vector<uint8_t> endpoint_pk_x;
  std::vector<uint8_t> endpoint_prst_k;
  // hkEnrollments_t enrollments;
};

struct hkIssuer_t
{
  std::vector<uint8_t> issuer_id;
  std::vector<uint8_t> issuer_pk;
  std::vector<uint8_t> issuer_pk_x;
  std::vector<hkEndpoint_t> endpoints;
};

struct readerData_t
{
  readerData_t() : reader_sk(0), reader_pk(0), reader_pk_x(0), reader_gid(0), reader_id(0), issuers(0) {}
  std::vector<uint8_t> reader_sk;
  std::vector<uint8_t> reader_pk;
  std::vector<uint8_t> reader_pk_x;
  std::vector<uint8_t> reader_gid;
  std::vector<uint8_t> reader_id;
  std::vector<hkIssuer_t> issuers;
};

