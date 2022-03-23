/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: This file contains some defination related to file kds_core.c.
 * Create: 2020-06-28
 */

#ifndef KDS_CORE_TA_H
#define KDS_CORE_TA_H

#include "tee_internal_api.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "securec.h"

#define SHA256_OBJECT_MAX_LENGTH 32
#define BLOCK_SIZE_MAX 0x7D000
#define IV_SIZE 16
#define KDS_MAX_KEY_OBJECT_SIZE 512

#define ATTRIBUTE_NUM_ONE 1
#define ATTRIBUTE_NUM_TWO 2
#define ATTRIBUTE_NUM_THREE 3
#define DIVISION_NUM_TWO 2

#define CONST_CURVE_INFO 256

#define UUID_UINT16_COUNT 2
#define UUID_UINT8_COUNT 8

#ifndef EOK
#define EOK 0
#endif

#define MAX_KEY_SIZE 512
#define KDS_PK_MAX 128
#define KEY_MAX 128 // sharekey,wrapkey,kek length
#define ECC256_OBJECT_MAX_LENGTH 521
#define BLOCK_SIZE_MAX 0x7D000
#define MAX_KEY_OBJECT_SIZE 521
#define UUID_SIZE (sizeof(uint32_t) + UUID_UINT16_COUNT * sizeof(uint16_t) + UUID_UINT8_COUNT * sizeof(uint8_t))
#define KDS_DECRYPT_PARAMS_INIT_VALUE { { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 } }

typedef struct {
    uint8_t *dataPtr;
    size_t len;
} DataBlob;

typedef struct {
    DataBlob pubKey;
    DataBlob cipherData;
    DataBlob nonceData;
    DataBlob aadData;
    DataBlob tagData;
    DataBlob customData; /* the customized information */
    DataBlob extInfo;
} KdsDecryptParams;

typedef DataBlob ECCPubKey;
typedef DataBlob ECCPriKey;

typedef struct {
    DataBlob nonce;
    DataBlob aad;
    DataBlob tag;
    uint32_t mode;
} AesCcmParams;

typedef struct {
    uint8_t *cipherData;
    uint32_t *cipherLen;
    uint8_t *ivData;
    uint32_t *ivLen;
} AesCbcEncryptParams;

TEE_Result HmacSha256(const DataBlob *msgBlob, const DataBlob *hmacKey, DataBlob *hmacResult);

TEE_Result AesDecrypt(const DataBlob *keyData, const DataBlob *ivData, const DataBlob *cipherData,
    uint8_t *plantData, size_t *plantData_size);

TEE_Result TaAesCbcEncrypt(const DataBlob *keyData, const DataBlob *plantData, AesCbcEncryptParams *encryptParams);

TEE_Result KdsDecryptService(const KdsDecryptParams *decryptParams, DataBlob *out);

#endif
