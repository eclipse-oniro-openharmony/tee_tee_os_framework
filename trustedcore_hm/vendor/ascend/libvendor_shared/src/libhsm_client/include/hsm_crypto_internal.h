/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: HSM crypto api function head
 * Author: chenyao
 * Create: 2020-01-08
 */
#ifndef _HSM_CRYPTO_INTERNAL_H_
#define _HSM_CRYPTO_INTERNAL_H_

#include "hsm_public.h"
#include "hsm_crypto_api.h"

TEE_Result cipher_init_para_check(HSM_CIPHER_START_INFO *cipher_start_info);
TEE_Result cipher_init_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_CIPHER_START_INFO *cipher_start_info);
TEE_Result mac_init_para_check(HSM_MAC_START_INFO *mac_start_info);
TEE_Result mac_init_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_MAC_START_INFO *mac_start_info);
TEE_Result hash_init_para_check(HSM_HASH_START_INFO *hash_start_info);
TEE_Result hash_init_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_HASH_START_INFO *hash_start_info);
TEE_Result sign_init_para_check(HSM_SIGN_START_INFO *sign_start_info);
TEE_Result sign_init_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_SIGN_START_INFO *sign_start_info);
TEE_Result verify_init_para_check(HSM_VERIFY_START_INFO *verify_start_info);
TEE_Result verify_init_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_VERIFY_START_INFO *verify_start_info);

#endif
