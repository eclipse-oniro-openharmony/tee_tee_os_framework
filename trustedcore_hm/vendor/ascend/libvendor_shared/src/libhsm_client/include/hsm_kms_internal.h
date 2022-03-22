/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: HSM kms internal function head
 * Author: chenyao
 * Create: 2019-01-08
 */
#ifndef _HSM_KMS_INTERNAL_H_
#define _HSM_KMS_INTERNAL_H_

#include "hsm_public.h"
#include "hsm_kms_api.h"
#include "tee_service_public.h"

TEE_Result generate_symkey_para_check(HSM_GENERATE_SYMKEY_INFO *generate_symkey_info);
TEE_Result generate_symkey_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_GENERATE_SYMKEY_INFO *generate_symkey_info);
TEE_Result hsm_asymetickey_rsp(tee_service_ipc_msg_rsp *rsp, HSM_GENERATE_ASYMKEY_INFO *generate_asymkey_info,
    uint8_t *buffer_local);
TEE_Result generate_asymkey_para_check(HSM_GENERATE_ASYMKEY_INFO *generate_asymkey_info);
TEE_Result generate_asymkey_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_GENERATE_ASYMKEY_INFO *generate_asymkey_info);
TEE_Result  derive_huk_para_check(HSM_DERIVE_HUK_INFO *derive_huk_info);
TEE_Result derive_huk_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_DERIVE_HUK_INFO *derive_huk_info);
TEE_Result derive_key_para_check(HSM_DERIVE_KEY_INFO *derive_key_info);
TEE_Result derive_key_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_DERIVE_KEY_INFO *derive_key_info);
TEE_Result import_key_para_check(HSM_IMPORT_KEY_INFO *import_key_info);
TEE_Result import_key_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_IMPORT_KEY_INFO *import_key_info);
TEE_Result exchange_pubkey_para_check(HSM_EXCHANGE_PUBKEY_INFO *exchange_pubkey);
TEE_Result exchange_pubkey_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_EXCHANGE_PUBKEY_INFO *exchange_pubkey);
TEE_Result exchange_agree_key_para_check(HSM_EXCHANGE_KEY_INFO *exchange_agree_key);
TEE_Result exchange_agree_key_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_EXCHANGE_KEY_INFO *exchange_agree_key);
TEE_Result update_prokey_para_check(HSM_UPDATE_PROKEY_INFO *update_prokey_info);
TEE_Result update_prokey_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_UPDATE_PROKEY_INFO *update_prokey_info);
TEE_Result update_keyauth_para_check(HSM_UPDATE_KEYAUTH_INFO *update_keyauth_info);
TEE_Result update_keyauth_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_UPDATE_KEYAUTH_INFO *update_keyauth_info);
TEE_Result delete_key_para_check(HSM_DELETE_KEY_INFO *delete_key_info);
TEE_Result delete_key_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_DELETE_KEY_INFO *delete_key_info);
TEE_Result export_key_para_check(HSM_EXPORT_KEY_INFO *export_key_info);
TEE_Result export_key_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_EXPORT_KEY_INFO *export_key_info);

#endif
