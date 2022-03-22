/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definations for kds phase one.
 * Create: 2020-06-28
 */

#ifndef KDS_PHASE1_H
#define KDS_PHASE1_H

#include "tee_core_api.h"

#define KDS_UINT_MAX 0xFFFFFFFFul
#define MAX_MALLOC_LEN (unsigned int)4096

/* Definations for handle Ta command. */
#define PARAM_ZERO_UINT32_COUNT 4
#define PARAM_ONE_UINT32_COUNT 2

#define AES_CCM_NONCE_SIZE 7
#define TMP_PK_MAX 256
#define EXT_INFO_SIZE 16
#define MAX_CIPHER_SIZE 528
#define CIPHER_MIN 16
#define CUSTOME_MIN 8
#define TMPPK_MIN 8

#define TA_CUASTOM_SIZE 16
#define TAG_SIZE 16
#define AAD_SIZE 32

#define TA_PARAM_ONE_SIZE (sizeof(uint32_t) * 4 + AES_CCM_NONCE_SIZE + AAD_SIZE + TAG_SIZE + CIPHER_MIN + TAG_SIZE)
#define TA_PARAM_TWO_SIZE (sizeof(uint32_t) * 2 + CUSTOME_MIN + EXT_INFO_SIZE)
#define TA_PARAM_THREE_SIZE (sizeof(uint32_t) * 2 + TMPPK_MIN)

TEE_Result HandleTaCommandDecrypt(uint32_t paramTypes, TEE_Param *params);

#endif