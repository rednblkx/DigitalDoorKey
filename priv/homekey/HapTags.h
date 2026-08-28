typedef enum
{
  kReader_Operation = 0x01,
  kReader_Device_Credential_Request = 0x04,
  kReader_Device_Credential_Response = 0x05,
  kReader_Reader_Key_Request = 0x06,
  kReader_Reader_Key_Response = 0x07,
} Reader_Tags;

typedef enum
{
  kReader_Operation_Read = 0x01,
  kReader_Operation_Write = 0x02,
  kReader_Operation_Remove = 0x03,
} Reader_Operation;

typedef enum
{
  kReader_Req_Key_Type = 0x01,
  kReader_Req_Reader_Private_Key = 0x02,
  kReader_Req_Identifier = 0x03,
  kReader_Req_Key_Identifier = 0x04, // This is only relevant for "remove" operation
  kRequest_Reader_Key_Request = 0x06
} Reader_Key_Request;

typedef enum
{
  kReader_Res_Key_Identifier = 0x01,
  kReader_Res_Status = 0x02,
  kReader_Res_Reader_Key_Response = 0x07
} Reader_Key_Response;

typedef enum
{
  kDevice_Req_Key_Type = 0x01,
  kDevice_Req_Public_Key = 0x02,
  kDevice_Req_Issuer_Key_Identifier = 0x03,
  kDevice_Req_Key_State = 0x04,
  kDevice_Req_Key_Identifier = 0x05 // This is only relevant for "remove" operation
} Device_Credential_Request;

typedef enum
{
  kDevice_Res_Key_Identifier = 0x01,
  kDevice_Res_Issuer_Key_Identifier = 0x02,
  kDevice_Res_Status = 0x03,
  kDevice_Credential_Response = 0x05
} Device_Credential_Response;

typedef enum
{
  SUCCESS = 0,
  OUT_OF_RESOURCES = 1,
  DUPLICATE = 2,
  DOES_NOT_EXIST = 3,
  NOT_SUPPORTED = 4
} OPERATION_STATUS;
