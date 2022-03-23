/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definations for kds phase three.
 * Create: 2020-06-28
 */

#ifndef KDS_PHASE3_H
#define KDS_PHASE3_H

#include "tee_core_api.h"

#define MAX_EXTEND_INFO_LEN 1024
#define TARGET_PLATFORM_SIZE 16

#define TAG_SIZE 16
#define AAD_SIZE 32
#define TMP_PK_SIZE 128
#define NONCE_SIZE 32
#define CIPHER_SIZE 512
#define CUSTMIZED_INFO_SIZE 32
#define METADATA_SIZE 1024
#define PROCESSINFO_SIZE 1024
#define RESULT_SIZE 512

#define PROC_NAME_LEN 32 /* Length of process name. */
#define HASH_LEN 32 /* Length of hash. */
#define RESERVED_LEN 188 /* Length of reserved for future. */
#define SIGNATURE_LEN 256 /* Length of signature. */

typedef struct {
    uint32_t ver; /* Little endian, version of this structure, start with 0. */
    char procName[PROC_NAME_LEN]; /* Process name, c string, null-terminated. */
    uint8_t hash[HASH_LEN]; /* Sha256 of all “RE” segments. */
    uint8_t reserved[RESERVED_LEN]; /* Reserved for future, pad structure to 512 bytes. */
    uint8_t signature[SIGNATURE_LEN]; /* Signature of structure, RSA2048+SHA256. */
} ProcessMetadata;

typedef struct {
    uint32_t reqType;
    uint32_t extInfoSize;
    uint8_t targetPlatformId[TARGET_PLATFORM_SIZE];
    uint8_t extInfo[MAX_EXTEND_INFO_LEN];
} KdsGidReqInfo;

typedef struct {
    uint32_t tmpPkSize;
    uint32_t nonceSize;
    uint32_t aadSize;
    uint32_t cipherSize;
    uint32_t tagSize;
    uint32_t custmizedInfoSize;
    uint32_t metadataSize;
    uint32_t processInfoSize; // Size of extension information.
    uint8_t tmpPk[TMP_PK_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t aad[AAD_SIZE];
    uint8_t cipher[CIPHER_SIZE];
    uint8_t tag[TAG_SIZE];
    uint8_t custmizedInfo[CUSTMIZED_INFO_SIZE];
    uint8_t metadata[METADATA_SIZE];
    uint8_t processInfo[PROCESSINFO_SIZE];
} KdsGidDataInfos;

typedef struct {
    uint32_t resultSize;
    uint32_t processInfoSize; // Size of extension information.
    uint8_t result[RESULT_SIZE];
    uint8_t processInfo[PROCESSINFO_SIZE];
} KdsGidResultInfo;

TEE_Result HandleGidCommandFromCa(uint32_t paramTypes, TEE_Param *params);

#endif