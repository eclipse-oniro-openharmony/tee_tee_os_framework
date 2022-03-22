/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: This file contains some common definations.
 * Create: 2020-06-28
 */

#ifndef KDS_DEFS_TA_H
#define KDS_DEFS_TA_H

#include "securectype.h"

#define INDEX_ZERO 0
#define INDEX_ONE 1
#define INDEX_TWO 2
#define INDEX_THREE 3

#define OFFSET_ONE 1
#define OFFSET_TWO 2
#define OFFSET_THREE 3

#define FREE_DATA_BLOB(blob) \
{ \
    if (((blob) != NULL) && ((blob)->dataPtr != NULL)) { \
        memset_s((blob)->dataPtr, (blob)->len, 0, (blob)->len); \
        TEE_Free((blob)->dataPtr); \
        (blob)->dataPtr = NULL; \
        (blob)->len = 0; \
    } \
}

typedef enum {
    KDS_SUCCESS = 0x00000000,
    KDS_ERR_BAD_ACCESS = 0x7A000001,
    KDS_CA_ACCESS = 0x7A000002,
    KDS_TA_ACCESS = 0x7A000003,
    KDS_FAIL = -1,
    KDS_ERROR_MAC_VERIFY_FAIL = -2,
    KDS_ERROR_REQTYPE_UNSUPPORT = -3,
    KDS_ERROR_REQTYPE_INVALID = -4,
    KDS_ERROR_PERMISSION_ERROR = -5,
    KDS_ERROR_BAD_PARAMETERS = -6,
} KdsResultCode;

typedef enum {
    KDS_OK = 0,
} KdsError;

typedef enum {
    KDS_REQ_ENCRYPT_AES_CBC_128 = 0x0101,
    KDS_REQ_DECRYPT_AES_CBC_128 = 0x0102,
    KDS_REQ_ENCRYPT_AES_CBC_256 = 0x0103,
    KDS_REQ_DECRYPT_AES_CBC_256 = 0x0104,
    KDS_REQ_HASH_GENERATE_HMAC_SHA256 = 0x0201,
    KDS_REQ_HASH_VERIFY_HMAC_SHA256 = 0x0202,
    KDS_REQ_DECRYPT_GID_CIPHER = 0x0A01, // decryption-request using cipher suite "AES-CCM-HMACSHA256-ECDHP256"
} KdsReqType;

typedef enum {
    KDS_AES_128 = 0X00000101,
    KDS_AES_256 = 0X00000102,
    KDS_HMAC = 0X00000201,
} KdsKeyType;

typedef enum {
    KDS_CMD_ID_REQ = 0,
    KDS_CMD_DECRYPT = 1,
    KDS_CMD_CA_GID_REQ = 2,
} KdsCommandId;

// kds 3.0
typedef enum {
    KDS_FUNCTION_ERROR = -1, // Function failed(a TEE internal error occurred)
    KDS_MAC_VERIFY_FAIL = -2, // don't have relationship with gid
    KDS_REQTYPE_INVALID = -3, // REQTYPE not support
    KDS_PERMISSION_ERROR = -4, // don't have relationship with gid
    KDS_AUTH_ERROR = -5, // auth error
    KDS_PLATFORM_ERROR = -6, // platform error
} KdsGidTag;

#endif