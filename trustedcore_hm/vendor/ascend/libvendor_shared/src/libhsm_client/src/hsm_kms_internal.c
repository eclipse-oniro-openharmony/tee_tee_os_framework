/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: HSM kms internal function.
 * Author: chenyao
 * Create: 2020-01-08
 * Notes:
 * History: 2020-01-08 chenyao create hsm_kms functions.
 */
#include <stdarg.h>
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "securec.h"
#include "string.h"
#include "tee_service_public.h"
#include "hsm_kms_api.h"
#include "hsm_public.h"

TEE_Result generate_symkey_para_check(HSM_GENERATE_SYMKEY_INFO *generate_symkey_info)
{
    uint32_t auth_size;

    if ((generate_symkey_info == NULL) || (generate_symkey_info->symkey_auth == NULL)) {
        return TEE_ERROR_NO_DATA;
    }
    auth_size = generate_symkey_info->symkey_authsize;

    if (generate_symkey_info->symkey_protectmsg == NULL ||
        generate_symkey_info->symkey.cryptokeyelementvalueref == NULL) {
        return TEE_ERROR_NO_DATA;
    }

    if (auth_size > HSM_AUTH_MAX_SIZE) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result generate_symkey_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_GENERATE_SYMKEY_INFO *generate_symkey_info)
{
    uint32_t auth_size = generate_symkey_info->symkey_authsize;
    uint32_t hsm_symkey_head_size = HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + HSM_IV_SIZE;
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};
    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_ALG_SIZE, &generate_symkey_info->alg_id, HSM_ALG_SIZE) != EOK) {
        goto GENERATE_SYMKEY_Ex_Handle;
    }

    /* key_element head */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE, HSM_KEY_ELEMENT_SIZE,
        &generate_symkey_info->symkey, HSM_KEY_ELEMENT_SIZE) != EOK) {
        goto GENERATE_SYMKEY_Ex_Handle;
    }

    /* auth_size + 16 */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        goto GENERATE_SYMKEY_Ex_Handle;
    }

    /* auth_size */
    if (memmove_s(*buffer_local + hsm_symkey_head_size, auth_size, generate_symkey_info->symkey_auth,
        auth_size) != EOK) {
        goto GENERATE_SYMKEY_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

GENERATE_SYMKEY_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result hsm_asymetickey_rsp(tee_service_ipc_msg_rsp *rsp, HSM_GENERATE_ASYMKEY_INFO *generate_asymkey_info,
    uint8_t *buffer_local)
{
    uint32_t size0;
    uint32_t size1;
    uint32_t size2;
    uint32_t size3;

    size0 = (uint32_t)(rsp->msg.args_data.arg2 >> HSM_CONST_SHIFT_32) - HSM_KEY_ELEMENT_SIZE;
    size1 = (uint32_t)(rsp->msg.args_data.arg2);
    size2 = (uint32_t)(rsp->msg.args_data.arg3 >> HSM_CONST_SHIFT_32) - HSM_KEY_ELEMENT_SIZE;
    size3 = (uint32_t)(rsp->msg.args_data.arg3);
    if ((size0 > HSM_ASYMKEY_MAX_SIZE) || (size1 > HSM_PROTECTMSG_MAX_SIZE) || (size2 > HSM_ASYMKEY_MAX_SIZE) ||
        (size3 > HSM_PROTECTMSG_MAX_SIZE)) {
        return TEE_FAIL;
    }
    if (memmove_s(generate_asymkey_info->prikey.cryptokeyelementvalueref, size0,
        buffer_local + HSM_KEY_ELEMENT_SIZE, size0) != EOK) {
        return TEE_FAIL;
    }
    if (memmove_s(generate_asymkey_info->prikey_protectmsg, size1,
        buffer_local + size0 + HSM_KEY_ELEMENT_SIZE, size1) != EOK) {
        return TEE_FAIL;
    }
    if (memmove_s(generate_asymkey_info->pubkey.cryptokeyelementvalueref, size2,
        buffer_local + size0 + HSM_KEY_ELEMENT_SIZE + HSM_KEY_ELEMENT_SIZE + size1, size2) != EOK) {
        return TEE_FAIL;
    }
    if (memmove_s(generate_asymkey_info->pubkey_protectmsg, size3,
        buffer_local + size0 + size1 + size2 + HSM_KEY_ELEMENT_SIZE + HSM_KEY_ELEMENT_SIZE, size3) != EOK) {
        return TEE_FAIL;
    }

    return TEE_SUCCESS;
}

TEE_Result generate_asymkey_para_check(HSM_GENERATE_ASYMKEY_INFO *generate_asymkey_info)
{
    uint32_t auth_size;

    if ((generate_asymkey_info == NULL) || (generate_asymkey_info->key_auth == NULL)) {
        return TEE_ERROR_NO_DATA;
    }
    auth_size = generate_asymkey_info->key_authsize;

    if ((generate_asymkey_info->pubkey_protectmsg == NULL) || (generate_asymkey_info->prikey_protectmsg == NULL) ||
        (generate_asymkey_info->pubkey.cryptokeyelementvalueref == NULL) ||
        (generate_asymkey_info->prikey.cryptokeyelementvalueref == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if (auth_size > HSM_AUTH_MAX_SIZE) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result generate_asymkey_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_GENERATE_ASYMKEY_INFO *generate_asymkey_info)
{
    uint32_t hsm_asymkey_head_size = HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + HSM_KEY_ELEMENT_SIZE + HSM_IV_SIZE;
    uint32_t auth_size = generate_asymkey_info->key_authsize;
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_ALG_SIZE, &generate_asymkey_info->alg_id, HSM_ALG_SIZE) != EOK) {
        goto GENERATE_ASYMKEY_Ex_Handle;
    }

    /* key_element head */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE, HSM_KEY_ELEMENT_SIZE,
        &generate_asymkey_info->prikey, HSM_KEY_ELEMENT_SIZE) != EOK) {
        goto GENERATE_ASYMKEY_Ex_Handle;
    }

    /* key_element head */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE, HSM_KEY_ELEMENT_SIZE,
        &generate_asymkey_info->pubkey, HSM_KEY_ELEMENT_SIZE) != EOK) {
        goto GENERATE_ASYMKEY_Ex_Handle;
    }

    /* auth_size + 16 */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + HSM_KEY_ELEMENT_SIZE, HSM_IV_SIZE,
        tmp, HSM_IV_SIZE) != EOK) {
        goto GENERATE_ASYMKEY_Ex_Handle;
    }

    /* auth_size */
    if (memmove_s(*buffer_local + hsm_asymkey_head_size, auth_size, generate_asymkey_info->key_auth,
        auth_size) != EOK) {
        goto GENERATE_ASYMKEY_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

GENERATE_ASYMKEY_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result derive_huk_para_check(HSM_DERIVE_HUK_INFO *derive_huk_info)
{
    uint32_t salt_size;
    uint32_t auth_size;

    if ((derive_huk_info == NULL) || (derive_huk_info->key_auth == NULL)) {
        return TEE_ERROR_NO_DATA;
    }
    salt_size = derive_huk_info->salt_size;
    auth_size = derive_huk_info->key_authsize;

    if ((derive_huk_info->key_protectmsg == NULL) || (derive_huk_info->salt == NULL) ||
        (derive_huk_info->c_key.cryptokeyelementvalueref == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((salt_size > HSM_SALT_MAX_SIZE) || (auth_size > HSM_AUTH_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result derive_huk_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_DERIVE_HUK_INFO *derive_huk_info)
{
    uint32_t salt_size = derive_huk_info->salt_size;
    uint32_t auth_size = derive_huk_info->key_authsize;
    uint32_t hsm_huk_head_size = HSM_ALG_SIZE + HSM_SALT_SIZE + HSM_IRT_NUM_SIZE + HSM_KEY_ELEMENT_SIZE;
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_ALG_SIZE, &derive_huk_info->alg_id, HSM_ALG_SIZE) != EOK) {
        goto DERIVE_HUK_Ex_Handle;
    }
    if (memmove_s(*buffer_local + HSM_ALG_SIZE, HSM_SALT_SIZE, &derive_huk_info->salt_size, HSM_SALT_SIZE) != EOK) {
        goto DERIVE_HUK_Ex_Handle;
    }
    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_SALT_SIZE, HSM_IRT_NUM_SIZE,
        &derive_huk_info->irt_num, HSM_IRT_NUM_SIZE) != EOK) {
        goto DERIVE_HUK_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_SALT_SIZE + HSM_IRT_NUM_SIZE, salt_size,
        derive_huk_info->salt, salt_size) != EOK) {
        goto DERIVE_HUK_Ex_Handle;
    }

    /* key_element head */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_SALT_SIZE + HSM_IRT_NUM_SIZE + salt_size, HSM_KEY_ELEMENT_SIZE,
        &derive_huk_info->c_key, HSM_KEY_ELEMENT_SIZE) != EOK) {
        goto DERIVE_HUK_Ex_Handle;
    }

    /* auth_size + 16 */
    if (memmove_s(*buffer_local + hsm_huk_head_size + salt_size, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        goto DERIVE_HUK_Ex_Handle;
    }

    /* auth_size */
    if (memmove_s(*buffer_local + hsm_huk_head_size + salt_size + HSM_IV_SIZE, auth_size,
        derive_huk_info->key_auth, auth_size) != EOK) {
        goto DERIVE_HUK_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

DERIVE_HUK_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

static TEE_Result derive_key_info2_check(HSM_DERIVE_KEY_INFO *derive_key_info)
{
    if ((derive_key_info->source_key.cryptokeyelementvalueref == NULL) || (derive_key_info->salt == NULL) ||
        (derive_key_info->target_key_protectmsg == NULL) ||
        (derive_key_info->target_key.cryptokeyelementvalueref == NULL)) {
        tloge("derive_key_info2_check failed!\n");
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

static TEE_Result derive_key_info1_check(HSM_DERIVE_KEY_INFO *derive_key_info)
{
    if ((derive_key_info == NULL) || (derive_key_info->source_key_auth == NULL) ||
        (derive_key_info->target_key_auth == NULL)) {
        tloge("derive_key_info1_check failed!\n");
        return TEE_ERROR_NO_DATA;
    }

    if ((derive_key_info->source_key_protectmsg == NULL) || (derive_key_info->salt == NULL) ||
        (derive_key_info->target_key_protectmsg == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

static TEE_Result derive_key_info_check(HSM_DERIVE_KEY_INFO *derive_key_info)
{
    TEE_Result state;

    state = derive_key_info1_check(derive_key_info);
    if (state != TEE_SUCCESS) {
        return state;
    }

    state = derive_key_info2_check(derive_key_info);
    return state;
}

TEE_Result derive_key_para_check(HSM_DERIVE_KEY_INFO *derive_key_info)
{
    uint32_t salt_size = derive_key_info->salt_size;
    uint32_t target_key_size = derive_key_info->target_key.cryptokeyelementsize;
    uint32_t source_key_size = derive_key_info->source_key.cryptokeyelementsize;
    uint32_t source_auth_size = derive_key_info->source_key_authsize;
    uint32_t target_auth_size = derive_key_info->target_key_authsize;

    if (derive_key_info_check(derive_key_info) != TEE_SUCCESS) {
        tloge("derive_key_info_check failed!\n");
        return TEE_ERROR_NO_DATA;
    }

    if ((salt_size > HSM_SALT_MAX_SIZE) || (target_auth_size > HSM_AUTH_MAX_SIZE) ||
        (source_auth_size > HSM_AUTH_MAX_SIZE) || (target_key_size > HSM_ASYMKEY_MAX_SIZE) ||
        (source_key_size > HSM_ASYMKEY_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

static TEE_Result derive_key_data_move0(uint8_t *buffer_local, HSM_DERIVE_KEY_INFO *derive_key_info)
{
    uint32_t buffer_offset = 0;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    if (memmove_s(buffer_local + buffer_offset, HSM_ALG_SIZE, &derive_key_info->alg_id, HSM_ALG_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_ALG_SIZE;

    if (memmove_s(buffer_local + buffer_offset, HSM_SALT_SIZE, &derive_key_info->salt_size, HSM_SALT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_SALT_SIZE;

    if (memmove_s(buffer_local + buffer_offset, HSM_IRT_NUM_SIZE,
        &derive_key_info->irt_num, HSM_IRT_NUM_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_IRT_NUM_SIZE;

    if (memmove_s(buffer_local + buffer_offset, derive_key_info->salt_size,
        derive_key_info->salt, derive_key_info->salt_size) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += derive_key_info->salt_size;

    /* target key_element head */
    if (memmove_s(buffer_local + buffer_offset, HSM_KEY_ELEMENT_SIZE,
        &derive_key_info->target_key, HSM_KEY_ELEMENT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_KEY_ELEMENT_SIZE;

    /* auth_size + 16 */
    if (memmove_s(buffer_local + buffer_offset, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        return TEE_FAIL;
    }

    return TEE_SUCCESS;
}

static TEE_Result derive_key_data_move1(uint8_t *buffer_local, HSM_DERIVE_KEY_INFO *derive_key_info)
{
    uint32_t buffer_offset = HSM_ALG_SIZE + HSM_SALT_SIZE + HSM_IRT_NUM_SIZE +
        derive_key_info->salt_size + HSM_KEY_ELEMENT_SIZE + HSM_IV_SIZE;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    if (memmove_s(buffer_local + buffer_offset, derive_key_info->target_key_authsize,
        derive_key_info->target_key_auth, derive_key_info->target_key_authsize) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += derive_key_info->target_key_authsize;

    /* source key_element head */
    if (memmove_s(buffer_local + buffer_offset, HSM_KEY_ELEMENT_SIZE,
        &derive_key_info->source_key, HSM_KEY_ELEMENT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_KEY_ELEMENT_SIZE;

    if (memmove_s(buffer_local + buffer_offset, derive_key_info->source_key.cryptokeyelementsize,
        derive_key_info->source_key.cryptokeyelementvalueref,
        derive_key_info->source_key.cryptokeyelementsize) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += derive_key_info->source_key.cryptokeyelementsize;

    if (memmove_s(buffer_local + buffer_offset, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_IV_SIZE;

    if (memmove_s(buffer_local + buffer_offset, derive_key_info->source_key_authsize,
        derive_key_info->source_key_auth, derive_key_info->source_key_authsize) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += derive_key_info->source_key_authsize;

    if (memmove_s(buffer_local + buffer_offset, derive_key_info->source_key_authsize + HSM_KEY_PROTECT_SIZE,
        derive_key_info->source_key_protectmsg, derive_key_info->source_key_authsize + HSM_KEY_PROTECT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    return TEE_SUCCESS;
}

TEE_Result derive_key_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_DERIVE_KEY_INFO *derive_key_info)
{
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint32_t ret;

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, dst_size);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = derive_key_data_move0(*buffer_local, derive_key_info);
    if (ret != TEE_SUCCESS) {
        goto DERIVE_KEY_Ex_Handle;
    }

    ret = derive_key_data_move1(*buffer_local, derive_key_info);
    if (ret != TEE_SUCCESS) {
        goto DERIVE_KEY_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

DERIVE_KEY_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result import_key_para_check(HSM_IMPORT_KEY_INFO *import_key_info)
{
    uint32_t salt_size;
    uint32_t key_len;
    uint32_t import_key_size;
    uint32_t import_auth_size;

    if ((import_key_info == NULL) || (import_key_info->import_key_auth == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    salt_size = import_key_info->salt_size;
    key_len = import_key_info->import_key.cryptokeyelementsize;
    import_key_size = key_len + HSM_KEY_ELEMENT_SIZE + HSM_KEY_HEAD_SIZE;
    import_auth_size = import_key_info->import_key_authsize;

    if ((import_key_info->import_key_protectmsg == NULL) || (import_key_info->salt == NULL) ||
        (import_key_info->import_key_info == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if (import_key_info->import_key.cryptokeyelementvalueref == NULL) {
        return TEE_ERROR_NO_DATA;
    }

    if ((salt_size > HSM_SALT_MAX_SIZE) || (import_auth_size > HSM_AUTH_MAX_SIZE) ||
        (import_key_size > HSM_ASYMKEY_MAX_SIZE) || (key_len > HSM_ASYMKEY_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result import_key_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_IMPORT_KEY_INFO *import_key_info)
{
    uint32_t salt_size = import_key_info->salt_size;
    uint32_t key_len = import_key_info->import_key.cryptokeyelementsize;
    uint32_t import_key_size = key_len + HSM_KEY_ELEMENT_SIZE + HSM_KEY_HEAD_SIZE;
    uint32_t import_auth_size = import_key_info->import_key_authsize;

    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_ALG_SIZE, &import_key_info->alg_id, HSM_ALG_SIZE) != EOK) {
        goto IMPORT_KEY_Ex_Handle;
    }
    if (memmove_s(*buffer_local + HSM_ALG_SIZE, HSM_SALT_SIZE, &import_key_info->salt_size, HSM_SALT_SIZE) != EOK) {
        goto IMPORT_KEY_Ex_Handle;
    }
    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_SALT_SIZE, HSM_IRT_NUM_SIZE,
        &import_key_info->irt_num, HSM_IRT_NUM_SIZE) != EOK) {
        goto IMPORT_KEY_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_KEY_HEAD_SIZE, salt_size, import_key_info->salt, salt_size) != EOK) {
        goto IMPORT_KEY_Ex_Handle;
    }

    /* import key */
    if (memmove_s(*buffer_local + HSM_KEY_HEAD_SIZE + salt_size, import_key_size,
        import_key_info->import_key_info, import_key_size) != EOK) {
        goto IMPORT_KEY_Ex_Handle;
    }

    /* key elemrnt */
    if (memmove_s(*buffer_local + HSM_KEY_HEAD_SIZE + salt_size + import_key_size, HSM_KEY_ELEMENT_SIZE,
        &import_key_info->import_key, HSM_KEY_ELEMENT_SIZE) != EOK) {
        goto IMPORT_KEY_Ex_Handle;
    }

    /* auth_size + 16 */
    if (memmove_s(*buffer_local + HSM_KEY_HEAD_SIZE + HSM_KEY_ELEMENT_SIZE + salt_size + import_key_size, HSM_IV_SIZE,
        tmp, HSM_IV_SIZE) != EOK) {
        goto IMPORT_KEY_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_KEY_HEAD_SIZE + HSM_KEY_ELEMENT_SIZE + HSM_IV_SIZE + salt_size + import_key_size,
        import_auth_size, import_key_info->import_key_auth, import_auth_size) != EOK) {
        goto IMPORT_KEY_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

IMPORT_KEY_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result exchange_pubkey_para_check(HSM_EXCHANGE_PUBKEY_INFO *exchange_pubkey)
{
    uint32_t exchange_key_len;
    uint32_t exchange_pubkey_auth_size;

    if ((exchange_pubkey == NULL) || (exchange_pubkey->exchange_pubkey_auth == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    exchange_key_len = exchange_pubkey->exchange_pubkey.cryptokeyelementsize;
    exchange_pubkey_auth_size = exchange_pubkey->exchange_pubkey_authsize;

    if ((exchange_pubkey->exchange_pubkey_protectmsg == NULL) || (exchange_pubkey->generate_pubkey == NULL) ||
        (exchange_pubkey->generate_key_domain == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if (exchange_pubkey->exchange_pubkey.cryptokeyelementvalueref == NULL) {
        return TEE_ERROR_NO_DATA;
    }

    if ((exchange_key_len > HSM_ASYMKEY_MAX_SIZE) || (exchange_pubkey_auth_size > HSM_AUTH_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result exchange_pubkey_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_EXCHANGE_PUBKEY_INFO *exchange_pubkey)
{
    uint32_t exchange_key_len = exchange_pubkey->exchange_pubkey.cryptokeyelementsize;
    uint32_t exchange_pubkey_auth_size = exchange_pubkey->exchange_pubkey_authsize;
    uint32_t hsm_pubkey_head_size = HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + HSM_IV_SIZE;
    uint32_t exchange_pubkey_protect_size = HSM_KEY_PROTECT_SIZE + exchange_pubkey_auth_size;
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_ALG_SIZE, &exchange_pubkey->alg_id, HSM_ALG_SIZE) != EOK) {
        goto EXCHANGE_PUBKEY_Ex_Handle;
    }

    /* key elemrnt */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE, HSM_KEY_ELEMENT_SIZE,
        &exchange_pubkey->exchange_pubkey, HSM_KEY_ELEMENT_SIZE) != EOK) {
        goto EXCHANGE_PUBKEY_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE, exchange_key_len,
        exchange_pubkey->exchange_pubkey.cryptokeyelementvalueref, exchange_key_len) != EOK) {
        goto EXCHANGE_PUBKEY_Ex_Handle;
    }

    /* auth_size + 16 */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + exchange_key_len, HSM_IV_SIZE,
        tmp, HSM_IV_SIZE) != EOK) {
        goto EXCHANGE_PUBKEY_Ex_Handle;
    }

    if (memmove_s(*buffer_local + hsm_pubkey_head_size + exchange_key_len, exchange_pubkey_auth_size,
        exchange_pubkey->exchange_pubkey_auth, exchange_pubkey_auth_size) != EOK) {
        goto EXCHANGE_PUBKEY_Ex_Handle;
    }

    /* protect msg key */
    if (memmove_s(*buffer_local + hsm_pubkey_head_size + exchange_key_len + exchange_pubkey_auth_size,
        exchange_pubkey_protect_size, exchange_pubkey->exchange_pubkey_protectmsg,
        exchange_pubkey_protect_size) != EOK) {
        goto EXCHANGE_PUBKEY_Ex_Handle;
    }

    /* domain */
    if (memmove_s(*buffer_local + hsm_pubkey_head_size + exchange_key_len + exchange_pubkey_auth_size +
        exchange_pubkey_protect_size, HSM_DOMAIN_SIZE, exchange_pubkey->generate_key_domain, HSM_DOMAIN_SIZE) != EOK) {
        goto EXCHANGE_PUBKEY_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

EXCHANGE_PUBKEY_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

static TEE_Result exchange_agree_key2_check(HSM_EXCHANGE_KEY_INFO *exchange_agree_key)
{
    if ((exchange_agree_key->exchange_pubkey == NULL) || (exchange_agree_key->exchange_key_auth == NULL) ||
        (exchange_agree_key->agree_key_domain == NULL)) {
        tloge("exchange_agree_key2_check failed!\n");
        return TEE_ERROR_NO_DATA;
    }
    return TEE_SUCCESS;
}

static TEE_Result exchange_agree_key1_check(HSM_EXCHANGE_KEY_INFO *exchange_agree_key)
{
    if ((exchange_agree_key == NULL) || (exchange_agree_key->exchange_prikey_auth == NULL) ||
        (exchange_agree_key->exchange_key.cryptokeyelementvalueref == NULL)) {
        tloge("exchange_agree_key1_check0 failed!\n");
        return TEE_ERROR_NO_DATA;
    }

    if ((exchange_agree_key->exchange_prikey_protectmsg == NULL) || (exchange_agree_key->exchange_pubkey == NULL) ||
        (exchange_agree_key->exchange_prikey.cryptokeyelementvalueref == NULL)) {
        tloge("exchange_agree_key1_check1 failed!\n");
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

static TEE_Result exchange_agree_key_check(HSM_EXCHANGE_KEY_INFO *exchange_agree_key)
{
    TEE_Result state;

    state = exchange_agree_key1_check(exchange_agree_key);
    if (state != TEE_SUCCESS) {
        return state;
    }

    state = exchange_agree_key2_check(exchange_agree_key);
    return state;
}

TEE_Result exchange_agree_key_para_check(HSM_EXCHANGE_KEY_INFO *exchange_agree_key)
{
    uint32_t exchange_prikey_len = exchange_agree_key->exchange_prikey.cryptokeyelementsize;
    uint32_t exchange_key_len = exchange_agree_key->exchange_key.cryptokeyelementsize;
    uint32_t exchange_prikey_auth_size = exchange_agree_key->exchange_prikey_authsize;
    uint32_t exchange_key_auth_size = exchange_agree_key->exchange_key_authsize;
    uint32_t pubkey_len = exchange_agree_key->exchange_pubkey_len;
    uint32_t domain_size = exchange_agree_key->domain_size;

    if (exchange_agree_key_check(exchange_agree_key) != TEE_SUCCESS) {
        return TEE_ERROR_NO_DATA;
    }

    if ((exchange_prikey_auth_size > HSM_AUTH_MAX_SIZE) || (pubkey_len > HSM_ASYMKEY_MAX_SIZE) ||
        (exchange_key_len > HSM_ASYMKEY_MAX_SIZE) || (exchange_prikey_len > HSM_ASYMKEY_MAX_SIZE) ||
        (exchange_key_auth_size > HSM_AUTH_MAX_SIZE) || (domain_size > (HSM_ASYMKEY_MAX_SIZE + HSM_ASYMKEY_MAX_SIZE))) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

static TEE_Result exchange_agree_key_data_move0(uint8_t *buffer_local,
    HSM_EXCHANGE_KEY_INFO *exchange_agree_key)
{
    uint32_t buffer_offset = 0;
    uint8_t tmp[HSM_IV_SIZE] = {0};
    uint32_t exchange_key_len = exchange_agree_key->exchange_prikey.cryptokeyelementsize;
    uint32_t exchange_agreekey_protect_size = HSM_KEY_PROTECT_SIZE + exchange_agree_key->exchange_prikey_authsize;

    if (memmove_s(buffer_local, HSM_ALG_SIZE, &exchange_agree_key->alg_id, HSM_ALG_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_ALG_SIZE;

    /* key elemrnt */
    if (memmove_s(buffer_local + buffer_offset, HSM_KEY_ELEMENT_SIZE,
        &exchange_agree_key->exchange_prikey, HSM_KEY_ELEMENT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_KEY_ELEMENT_SIZE;

    if (memmove_s(buffer_local + buffer_offset, exchange_key_len,
        exchange_agree_key->exchange_prikey.cryptokeyelementvalueref, exchange_key_len) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += exchange_key_len;

    /* auth_size + 16 */
    if (memmove_s(buffer_local + buffer_offset, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_IV_SIZE;

    if (memmove_s(buffer_local + buffer_offset, exchange_agree_key->exchange_prikey_authsize,
        exchange_agree_key->exchange_prikey_auth, exchange_agree_key->exchange_prikey_authsize) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += exchange_agree_key->exchange_prikey_authsize;

    /* protect msg key */
    if (memmove_s(buffer_local + buffer_offset, exchange_agreekey_protect_size,
        exchange_agree_key->exchange_prikey_protectmsg, exchange_agreekey_protect_size) != EOK) {
        return TEE_FAIL;
    }

    return TEE_SUCCESS;
}

static TEE_Result exchange_agree_key_data_move1(uint8_t *buffer_local,
    HSM_EXCHANGE_KEY_INFO *exchange_agree_key)
{
    uint32_t exchange_key_len = exchange_agree_key->exchange_prikey.cryptokeyelementsize;
    uint32_t exchange_agreekey_protect_size = HSM_KEY_PROTECT_SIZE + exchange_agree_key->exchange_prikey_authsize;
    uint32_t buffer_offset = HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + exchange_key_len + HSM_IV_SIZE +
        exchange_agree_key->exchange_prikey_authsize + exchange_agreekey_protect_size;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    /* pubkey len and key element */
    if (memmove_s(buffer_local + buffer_offset, exchange_agree_key->exchange_pubkey_len,
        exchange_agree_key->exchange_pubkey, exchange_agree_key->exchange_pubkey_len) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += exchange_agree_key->exchange_pubkey_len;

    if (memmove_s(buffer_local + buffer_offset, HSM_KEY_ELEMENT_SIZE,
        &exchange_agree_key->exchange_key, HSM_KEY_ELEMENT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_KEY_ELEMENT_SIZE;

    /* iv and auth */
    if (memmove_s(buffer_local + buffer_offset, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_IV_SIZE;

    if (memmove_s(buffer_local + buffer_offset, exchange_agree_key->exchange_key_authsize,
        exchange_agree_key->exchange_key_auth, exchange_agree_key->exchange_key_authsize) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += exchange_agree_key->exchange_key_authsize;

    /* domain */
    if (memmove_s(buffer_local + buffer_offset, HSM_DOMAIN_SIZE,
        exchange_agree_key->agree_key_domain, HSM_DOMAIN_SIZE) != EOK) {
        return TEE_FAIL;
    }

    return TEE_SUCCESS;
}

TEE_Result exchange_agree_key_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_EXCHANGE_KEY_INFO *exchange_agree_key)
{
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint32_t ret;

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = exchange_agree_key_data_move0(*buffer_local, exchange_agree_key);
    if (ret != TEE_SUCCESS) {
        goto EXCHANGE_AGREE_KEY_Ex_Handle;
    }

    ret = exchange_agree_key_data_move1(*buffer_local, exchange_agree_key);
    if (ret != TEE_SUCCESS) {
        goto EXCHANGE_AGREE_KEY_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

EXCHANGE_AGREE_KEY_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result update_prokey_para_check(HSM_UPDATE_PROKEY_INFO *update_prokey_info)
{
    uint32_t key_size;
    uint32_t auth_size;

    if ((update_prokey_info == NULL) || (update_prokey_info->prokey_auth == NULL) ||
        (update_prokey_info->prokey_protectmsg == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    key_size = update_prokey_info->prokey.cryptokeyelementsize;
    auth_size = update_prokey_info->prokey_authsize;

    if (update_prokey_info->prokey.cryptokeyelementvalueref == NULL) {
        return TEE_ERROR_NO_DATA;
    }

    if ((auth_size > HSM_AUTH_MAX_SIZE) || (key_size > HSM_ASYMKEY_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result update_prokey_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_UPDATE_PROKEY_INFO *update_prokey_info)
{
    uint32_t key_size = update_prokey_info->prokey.cryptokeyelementsize;
    uint32_t auth_size = update_prokey_info->prokey_authsize;
    uint32_t promsg_size = auth_size + HSM_KEY_PROTECT_SIZE;
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};
    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* key_element head */
    if (memmove_s(*buffer_local, HSM_KEY_ELEMENT_SIZE, &update_prokey_info->prokey, HSM_KEY_ELEMENT_SIZE) != EOK) {
        goto UPDATE_PROTECT_KEY_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_KEY_ELEMENT_SIZE, key_size,
        update_prokey_info->prokey.cryptokeyelementvalueref, key_size) != EOK) {
        goto UPDATE_PROTECT_KEY_Ex_Handle;
    }

    /* auth_size + 16 */
    if (memmove_s(*buffer_local + key_size + HSM_KEY_ELEMENT_SIZE, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        goto UPDATE_PROTECT_KEY_Ex_Handle;
    }

    /* auth_size */
    if (memmove_s(*buffer_local + key_size + HSM_KEY_ELEMENT_SIZE + HSM_IV_SIZE, auth_size,
        update_prokey_info->prokey_auth, auth_size) != EOK) {
        goto UPDATE_PROTECT_KEY_Ex_Handle;
    }

    /* protect msg */
    if (memmove_s(*buffer_local + key_size + HSM_KEY_ELEMENT_SIZE + HSM_IV_SIZE + auth_size, promsg_size,
        update_prokey_info->prokey_protectmsg, promsg_size) != EOK) {
        goto UPDATE_PROTECT_KEY_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

UPDATE_PROTECT_KEY_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result update_keyauth_para_check(HSM_UPDATE_KEYAUTH_INFO *update_keyauth_info)
{
    uint32_t past_auth_size;
    uint32_t new_auth_size;

    if ((update_keyauth_info == NULL) || (update_keyauth_info->past_key_auth == NULL) ||
        (update_keyauth_info->key_protectmsg == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    past_auth_size = update_keyauth_info->past_key_authsize;
    new_auth_size = update_keyauth_info->new_key_authsize;

    if (update_keyauth_info->new_key_auth == NULL) {
        return TEE_ERROR_NO_DATA;
    }

    if ((past_auth_size > HSM_AUTH_MAX_SIZE) || (new_auth_size > HSM_AUTH_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result update_keyauth_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_UPDATE_KEYAUTH_INFO *update_keyauth_info)
{
    uint32_t past_auth_size = update_keyauth_info->past_key_authsize;
    uint32_t new_auth_size = update_keyauth_info->new_key_authsize;
    uint32_t promsg_size = past_auth_size + HSM_KEY_PROTECT_SIZE;
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};
    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        goto UPDATE_KEYAUTH_Ex_Handle;
    }

    /* key_element head */
    if (memmove_s(*buffer_local + HSM_IV_SIZE, past_auth_size, update_keyauth_info->past_key_auth,
        past_auth_size) != EOK) {
        goto UPDATE_KEYAUTH_Ex_Handle;
    }

    /* auth_size + 16 */
    if (memmove_s(*buffer_local + HSM_IV_SIZE + past_auth_size, promsg_size,
        update_keyauth_info->key_protectmsg, promsg_size) != EOK) {
        goto UPDATE_KEYAUTH_Ex_Handle;
    }

    /* 16 + new auth_size */
    if (memmove_s(*buffer_local + HSM_IV_SIZE + past_auth_size + promsg_size, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        goto UPDATE_KEYAUTH_Ex_Handle;
    }

    /* protect msg */
    if (memmove_s(*buffer_local + HSM_IV_TWICE_SIZE + past_auth_size + promsg_size, new_auth_size,
        update_keyauth_info->new_key_auth, new_auth_size) != EOK) {
        goto UPDATE_KEYAUTH_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

UPDATE_KEYAUTH_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result delete_key_para_check(HSM_DELETE_KEY_INFO *delete_key_info)
{
    uint32_t delete_auth_size;

    if ((delete_key_info == NULL) || (delete_key_info->delete_key_auth == NULL) ||
        (delete_key_info->delete_key_protectmsg == NULL)) {
        return TEE_ERROR_NO_DATA;
    }
    delete_auth_size = delete_key_info->delete_key_authsize;

    if (delete_auth_size > HSM_AUTH_MAX_SIZE) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result delete_key_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_DELETE_KEY_INFO *delete_key_info)
{
    uint32_t delete_auth_size = delete_key_info->delete_key_authsize;
    uint32_t promsg_size = delete_auth_size + HSM_KEY_PROTECT_SIZE;
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};
    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* key protect msg */
    if (memmove_s(*buffer_local, promsg_size, delete_key_info->delete_key_protectmsg, promsg_size) != EOK) {
        goto DELETE_KEY_Ex_Handle;
    }

    /* key_auth */
    if (memmove_s(*buffer_local + promsg_size, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        goto DELETE_KEY_Ex_Handle;
    }

    /* auth */
    if (memmove_s(*buffer_local + HSM_IV_SIZE + promsg_size, delete_auth_size,
        delete_key_info->delete_key_auth, delete_auth_size) != EOK) {
        goto DELETE_KEY_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

DELETE_KEY_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result export_key_para_check(HSM_EXPORT_KEY_INFO *export_key_info)
{
    uint32_t salt_size;
    uint32_t export_key_size;
    uint32_t export_auth_size;

    if ((export_key_info == NULL) || (export_key_info->export_key_auth == NULL)) {
        return TEE_ERROR_NO_DATA;
    }
    salt_size = export_key_info->salt_size;
    export_key_size = export_key_info->export_key.cryptokeyelementsize;
    export_auth_size = export_key_info->export_key_authsize;

    if ((export_key_info->export_key_protectmsg == NULL) || (export_key_info->salt == NULL) ||
        (export_key_info->export_key_info == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if (export_key_info->export_key.cryptokeyelementvalueref == NULL) {
        return TEE_ERROR_NO_DATA;
    }

    if ((salt_size > HSM_SALT_MAX_SIZE) || (export_auth_size > HSM_AUTH_MAX_SIZE) ||
        (export_key_size > HSM_ASYMKEY_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

static TEE_Result export_key_data_move(uint8_t *buffer_local, HSM_EXPORT_KEY_INFO *export_key_info)
{
    uint32_t buffer_offset;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    if (memmove_s(buffer_local, HSM_ALG_SIZE, &export_key_info->alg_id, HSM_ALG_SIZE) != EOK) {
        return TEE_FAIL;
    }

    if (memmove_s(buffer_local + HSM_ALG_SIZE, HSM_SALT_SIZE, &export_key_info->salt_size, HSM_SALT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset = HSM_ALG_SIZE + HSM_SALT_SIZE;

    if (memmove_s(buffer_local + buffer_offset, HSM_IRT_NUM_SIZE, &export_key_info->irt_num, HSM_IRT_NUM_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_IRT_NUM_SIZE;

    if (memmove_s(buffer_local + buffer_offset, export_key_info->salt_size,
        export_key_info->salt, export_key_info->salt_size) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += export_key_info->salt_size;

    /* export key */
    if (memmove_s(buffer_local + buffer_offset, HSM_KEY_ELEMENT_SIZE,
        &export_key_info->export_key, HSM_KEY_ELEMENT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_KEY_ELEMENT_SIZE;

    if (memmove_s(buffer_local + buffer_offset, export_key_info->export_key.cryptokeyelementsize,
        export_key_info->export_key.cryptokeyelementvalueref,
        export_key_info->export_key.cryptokeyelementsize) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += export_key_info->export_key.cryptokeyelementsize;

    /* auth_size + 16 */
    if (memmove_s(buffer_local + buffer_offset, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_IV_SIZE;

    if (memmove_s(buffer_local + buffer_offset, export_key_info->export_key_authsize,
        export_key_info->export_key_auth, export_key_info->export_key_authsize) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += export_key_info->export_key_authsize;

    /* protect msg */
    if (memmove_s(buffer_local + buffer_offset, HSM_KEY_PROTECT_SIZE + export_key_info->export_key_authsize,
        export_key_info->export_key_protectmsg, HSM_KEY_PROTECT_SIZE + export_key_info->export_key_authsize) != EOK) {
        return TEE_FAIL;
    }

    return TEE_SUCCESS;
}

TEE_Result export_key_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_EXPORT_KEY_INFO *export_key_info)
{
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint32_t ret;

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = export_key_data_move(*buffer_local, export_key_info);
    if (ret != TEE_SUCCESS) {
        goto EXPORT_KEY_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

EXPORT_KEY_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}
