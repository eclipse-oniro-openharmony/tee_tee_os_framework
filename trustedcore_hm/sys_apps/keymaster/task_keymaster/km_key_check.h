/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key check header
 * Create: 2020-02-13
 */
#ifndef __KM_KEY_CHECK_H
#define __KM_KEY_CHECK_H

#include "tee_internal_api.h"
#include "keyblob.h"
TEE_Result calculate_hmac(uint8_t *p, uint32_t keyblob_size, uint8_t *hmac_reslut, int *adaptable,
    const keyblob_head *keyblob, const keymaster_blob_t *application_id);

int32_t check_enforce_info(uint32_t enforced_len, uint32_t hw_sw_size, uint32_t param_size,
    const keymaster_key_param_t *params_enforced, uint32_t *extend_buf_size);

TEE_Result key_blob_internal_check(const keyblob_head *key_blob, uint32_t buff_len);
TEE_Result check_keyblob_version(const keyblob_head *keyblob);
TEE_Result rsa_keymaterial_internal_check(const uint8_t *keymaterial, uint32_t len);
TEE_Result check_compare_hmac(const uint8_t *p, uint32_t keyblob_size, const keyblob_head *key_blob,
                              const keymaster_blob_t *application_id, int valid_key_blob_ret);
TEE_Result verify_keyblob_before_delete(const keyblob_head *key_blob, uint32_t keyblob_size,
    const uint8_t *keyblob_buffer);
TEE_Result verify_keyblob(const keyblob_head *key_blob, uint32_t keyblob_size, const keymaster_blob_t *application_id);
TEE_Result keyblob_check(const keyblob_head *key_blob, uint32_t keyblob_size, const keymaster_blob_t *application_id);
TEE_Result upgrading_keyblob_check(keyblob_head *keyblob, uint32_t keyblob_size, keymaster_blob_t *application_id);
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
TEE_Result check_keyblob_rollback(const keyblob_head *keyblob);
#endif
#endif
