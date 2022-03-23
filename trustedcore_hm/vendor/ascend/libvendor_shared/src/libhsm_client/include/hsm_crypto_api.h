/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: hsm_api function
 * Author: chenyao
 * Create: 2020-02-09
 */
#ifndef _HSM_CRYPTO_API_H_
#define _HSM_CRYPTO_API_H_

#include "hsm_public.h"

typedef struct {
    uint32_t            alg_id;
    uint32_t            crypto_service;
    CRYPTO_KEY_ELEMENT  cipher_key;
    uint8_t             *iv_ptr;
    uint32_t            iv_size;
    uint8_t             *cipherkey_auth;
    uint32_t            cipherkey_authsize;
    uint8_t             *cipherkey_protectmsg;
    uint32_t            *session_handle;
    uint32_t            *max_chunk_size;
    uint32_t            *chunk_block_size;
} HSM_CIPHER_START_INFO;

typedef struct {
    uint32_t            session_handle;
    uint32_t            input_data_size;
    uint8_t             *input_data;
    uint32_t            *output_data_size;
    uint8_t             *output_data;
} HSM_CIPHER_PROCESS_INFO;

typedef struct {
    uint32_t            session_handle;
    uint32_t            *output_data_size;
    uint8_t             *output_data;
} HSM_CIPHER_FINISH_INFO;

typedef struct {
    uint32_t            alg_id;
    uint32_t            crypto_service;
    uint32_t            *session_handle;
    uint32_t            *max_chunk_size;
    uint32_t            *chunk_block_size;
} HSM_HASH_START_INFO;

typedef struct {
    uint32_t            session_handle;
    uint32_t            input_data_size;
    uint8_t             *input_data;
} HSM_HASH_PROCESS_INFO;

typedef struct {
    uint32_t            session_handle;
    uint32_t            *output_data_size;
    uint8_t             *output_data;
} HSM_HASH_FINISH_INFO;

typedef struct {
    uint32_t            alg_id;
    uint32_t            crypto_service;
    CRYPTO_KEY_ELEMENT  cipher_key;
    uint8_t             *cipherkey_auth;
    uint32_t            cipherkey_authsize;
    uint8_t             *cipherkey_protectmsg;
    uint32_t            *session_handle;
    uint32_t            *max_chunk_size;
    uint32_t            *chunk_block_size;
} HSM_MAC_START_INFO;

typedef struct {
    uint32_t            session_handle;
    uint32_t            input_data_size;
    uint8_t             *input_data;
} HSM_MAC_PROCESS_INFO;

typedef struct {
    uint32_t            session_handle;
    uint32_t            *output_data_size;
    uint8_t             *output_data;
} HSM_MAC_FINISH_INFO;

typedef struct {
    uint32_t            alg_id;
    uint32_t            crypto_service;
    CRYPTO_KEY_ELEMENT  cipher_key;
    uint8_t             *cipherkey_auth;
    uint32_t            cipherkey_authsize;
    uint8_t             *cipherkey_protectmsg;
    uint32_t            *session_handle;
    uint32_t            *max_chunk_size;
    uint32_t            *chunk_block_size;
} HSM_SIGN_START_INFO;

typedef struct {
    uint32_t            session_handle;
    uint32_t            input_data_size;
    uint8_t             *input_data;
} HSM_SIGN_PROCESS_INFO;

typedef struct {
    uint32_t            session_handle;
    uint32_t            *sign_size;
    uint8_t             *sign;
} HSM_SIGN_FINISH_INFO;

typedef struct {
    uint32_t            alg_id;
    uint32_t            crypto_service;
    CRYPTO_KEY_ELEMENT  cipher_key;
    uint8_t             *sign;
    uint32_t            sign_size;
    uint8_t             *cipherkey_auth;
    uint32_t            cipherkey_authsize;
    uint8_t             *cipherkey_protectmsg;
    uint32_t            *session_handle;
    uint32_t            *max_chunk_size;
    uint32_t            *chunk_block_size;
} HSM_VERIFY_START_INFO;

typedef struct {
    uint32_t            session_handle;
    uint32_t            input_data_size;
    uint8_t             *input_data;
} HSM_VERIFY_PROCESS_INFO;

typedef struct {
    uint32_t            session_handle;
    uint32_t            *verify_result;
} HSM_VERIFY_FINISH_INFO;

typedef struct {
    uint8_t             *random;
    uint32_t            random_size;
} HSM_GET_RANDOM_INFO;

TEE_Result TEE_HSM_CipherStart(uint32_t dev_id, HSM_CIPHER_START_INFO *cipher_start_info);
TEE_Result TEE_HSM_CipherProcess(uint32_t dev_id, HSM_CIPHER_PROCESS_INFO *cipher_process_info);
TEE_Result TEE_HSM_CipherFinish(uint32_t dev_id, HSM_CIPHER_FINISH_INFO *cipher_finish_info);
TEE_Result TEE_HSM_HashStart(uint32_t dev_id, HSM_HASH_START_INFO *hash_start_info);
TEE_Result TEE_HSM_HashProcess(uint32_t dev_id, HSM_HASH_PROCESS_INFO *hash_process_info);
TEE_Result TEE_HSM_HashFinish(uint32_t dev_id, HSM_HASH_FINISH_INFO *hash_finish_info);
TEE_Result TEE_HSM_MacStart(uint32_t dev_id, HSM_MAC_START_INFO *mac_start_info);
TEE_Result TEE_HSM_MacProcess(uint32_t dev_id, HSM_MAC_PROCESS_INFO *mac_process_info);
TEE_Result TEE_HSM_MacFinish(uint32_t dev_id, HSM_MAC_FINISH_INFO *mac_finish_info);
TEE_Result TEE_HSM_SignStart(uint32_t dev_id, HSM_SIGN_START_INFO *sign_start_info);
TEE_Result TEE_HSM_SignProcess(uint32_t dev_id, HSM_SIGN_PROCESS_INFO *sign_process_info);
TEE_Result TEE_HSM_SignFinish(uint32_t dev_id, HSM_SIGN_FINISH_INFO *sign_finish_info);
TEE_Result TEE_HSM_VerifyStart(uint32_t dev_id, HSM_VERIFY_START_INFO *verify_start_info);
TEE_Result TEE_HSM_VerifyProcess(uint32_t dev_id, HSM_VERIFY_PROCESS_INFO *verify_process_info);
TEE_Result TEE_HSM_VerifyFinish(uint32_t dev_id, HSM_VERIFY_FINISH_INFO *verify_finish_info);
TEE_Result TEE_HSM_GetRandom(uint32_t dev_id, HSM_GET_RANDOM_INFO *random_info);

#endif
