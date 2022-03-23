/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: HSM crypto api function
 * Author: chenyao
 * Create: 2020-01-08
 * Notes:
 * History: 2020-01-08 chenyao create hsm_crypto functions.
 */
#include <stdarg.h>
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "securec.h"
#include "string.h"
#include "tee_service_public.h"
#include "hsm_crypto_api.h"
#include "hsm_public.h"
#include "hsm_crypto_internal.h"

TEE_Result cipher_init_para_check(HSM_CIPHER_START_INFO *cipher_start_info)
{
    uint32_t key_size;
    uint32_t auth_size;

    if (cipher_start_info == NULL || cipher_start_info->cipherkey_auth == NULL) {
        return TEE_ERROR_NO_DATA;
    }
    key_size = cipher_start_info->cipher_key.cryptokeyelementsize;
    auth_size = cipher_start_info->cipherkey_authsize;

    if ((cipher_start_info->cipherkey_protectmsg == NULL) ||
        (cipher_start_info->cipher_key.cryptokeyelementvalueref == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((cipher_start_info->session_handle == NULL) || (cipher_start_info->max_chunk_size == NULL) ||
        (cipher_start_info->chunk_block_size == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((key_size > HSM_SYMKEY_MAX_SIZE) || (auth_size > HSM_AUTH_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((cipher_start_info->iv_size != 0) && (cipher_start_info->iv_ptr != NULL)) {
        if (cipher_start_info->iv_size != HSM_IV_MAX_SIZE) {
            return TEE_ERROR_NO_DATA;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result cipher_init_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_CIPHER_START_INFO *cipher_start_info)
{
    uint32_t key_size = cipher_start_info->cipher_key.cryptokeyelementsize;
    uint32_t auth_size = cipher_start_info->cipherkey_authsize;
    uint32_t cipher_head_size = HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + HSM_IV_SIZE;
    uint32_t promsg_size = cipher_start_info->cipherkey_authsize + HSM_KEY_PROTECT_SIZE;
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_ALG_SIZE, &cipher_start_info->alg_id, HSM_ALG_SIZE) != EOK) {
        goto CIPHER_INIT_Ex_Handle;
    }

    /* key_size + 32 */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE, HSM_KEY_ELEMENT_SIZE,
        &cipher_start_info->cipher_key, HSM_KEY_ELEMENT_SIZE) != EOK) {
        goto CIPHER_INIT_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE, key_size,
        cipher_start_info->cipher_key.cryptokeyelementvalueref, key_size) != EOK) {
        goto CIPHER_INIT_Ex_Handle;
    }

    /* auth_size + 16 */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + key_size, HSM_IV_SIZE, tmp,
        HSM_IV_SIZE) != EOK) {
        goto CIPHER_INIT_Ex_Handle;
    }

    /* auth_size */
    if (memmove_s(*buffer_local + cipher_head_size + key_size, auth_size,
        cipher_start_info->cipherkey_auth, auth_size) != EOK) {
        goto CIPHER_INIT_Ex_Handle;
    }

    /* promsg_size */
    if (memmove_s(*buffer_local + cipher_head_size + key_size + auth_size, promsg_size,
        cipher_start_info->cipherkey_protectmsg, promsg_size) != EOK) {
        goto CIPHER_INIT_Ex_Handle;
    }

    /* iv_size */
    if ((cipher_start_info->iv_size != 0) && (cipher_start_info->iv_ptr != NULL)) {
        if (memmove_s(*buffer_local + cipher_head_size + key_size + auth_size + promsg_size, cipher_start_info->iv_size,
            cipher_start_info->iv_ptr, cipher_start_info->iv_size) != EOK) {
            goto CIPHER_INIT_Ex_Handle;
        }
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

CIPHER_INIT_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result hash_init_para_check(HSM_HASH_START_INFO *hash_start_info)
{
    if (hash_start_info == NULL) {
        return TEE_ERROR_NO_DATA;
    }

    if ((hash_start_info->session_handle == NULL) || (hash_start_info->max_chunk_size == NULL) ||
        (hash_start_info->chunk_block_size == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result hash_init_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_HASH_START_INFO *hash_start_info)
{
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_ALG_SIZE, &hash_start_info->alg_id, HSM_ALG_SIZE) != EOK) {
        goto HASH_INIT_Ex_Handle2;
    }

    *buffer_size = dst_size;

    return TEE_SUCCESS;

HASH_INIT_Ex_Handle2:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result mac_init_para_check(HSM_MAC_START_INFO *mac_start_info)
{
    uint32_t key_size;
    uint32_t auth_size;

    if (mac_start_info == NULL) {
        return TEE_ERROR_NO_DATA;
    }
    key_size = mac_start_info->cipher_key.cryptokeyelementsize;
    auth_size = mac_start_info->cipherkey_authsize;

    if ((mac_start_info->session_handle == NULL) || (mac_start_info->max_chunk_size == NULL) ||
        (mac_start_info->chunk_block_size == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((key_size > HSM_SYMKEY_MAX_SIZE) || (auth_size > HSM_AUTH_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result mac_init_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_MAC_START_INFO *mac_start_info)
{
    uint32_t key_size = mac_start_info->cipher_key.cryptokeyelementsize;
    uint32_t auth_size = mac_start_info->cipherkey_authsize;
    uint32_t hsm_hash_head_size = HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + HSM_IV_SIZE;
    uint32_t promsg_size = auth_size + HSM_KEY_PROTECT_SIZE;
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_ALG_SIZE, &mac_start_info->alg_id, HSM_ALG_SIZE) != EOK) {
        goto MAC_INIT_Ex_Handle2;
    }

    if (memmove_s(*buffer_local + HSM_ALG_SIZE, HSM_KEY_ELEMENT_SIZE,
        &mac_start_info->cipher_key, HSM_KEY_ELEMENT_SIZE) != EOK) {
        goto MAC_INIT_Ex_Handle2;
    }

    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE, key_size,
        mac_start_info->cipher_key.cryptokeyelementvalueref, key_size) != EOK) {
        goto MAC_INIT_Ex_Handle2;
    }

    /* auth_size + 16 */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + key_size, HSM_IV_SIZE,
        tmp, HSM_IV_SIZE) != EOK) {
        goto MAC_INIT_Ex_Handle2;
    }

    /* auth_size */
    if (memmove_s(*buffer_local + hsm_hash_head_size + key_size, auth_size,
        mac_start_info->cipherkey_auth, auth_size) != EOK) {
        goto MAC_INIT_Ex_Handle2;
    }

    /* promsg_size */
    if (memmove_s(*buffer_local + hsm_hash_head_size + key_size + auth_size, promsg_size,
        mac_start_info->cipherkey_protectmsg, promsg_size) != EOK) {
        goto MAC_INIT_Ex_Handle2;
    }

    *buffer_size = dst_size;

    return TEE_SUCCESS;

MAC_INIT_Ex_Handle2:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result sign_init_para_check(HSM_SIGN_START_INFO *sign_start_info)
{
    uint32_t key_size;
    uint32_t auth_size;

    if ((sign_start_info == NULL) || (sign_start_info->cipherkey_auth == NULL)) {
        return TEE_ERROR_NO_DATA;
    }
    key_size = sign_start_info->cipher_key.cryptokeyelementsize;
    auth_size = sign_start_info->cipherkey_authsize;

    if ((sign_start_info->cipherkey_protectmsg == NULL) ||
        (sign_start_info->cipher_key.cryptokeyelementvalueref == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((sign_start_info->session_handle == NULL) || (sign_start_info->max_chunk_size == NULL) ||
        (sign_start_info->chunk_block_size == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((key_size > HSM_ASYMKEY_MAX_SIZE) || (auth_size > HSM_AUTH_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result sign_init_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_SIGN_START_INFO *sign_start_info)
{
    uint32_t key_size = sign_start_info->cipher_key.cryptokeyelementsize;
    uint32_t auth_size = sign_start_info->cipherkey_authsize;
    uint32_t hsm_sign_head_size = HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + HSM_IV_SIZE;
    uint32_t promsg_size = auth_size + HSM_KEY_PROTECT_SIZE;
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};
    uint32_t salt_size = HSM_SIGN_VER_SALT_LEN;
    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_ALG_SIZE, &sign_start_info->alg_id, HSM_ALG_SIZE) != EOK) {
        goto SIGN_INIT_Ex_Handle;
    }

    /* key_size + 32 */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE, HSM_KEY_ELEMENT_SIZE,
        &sign_start_info->cipher_key, HSM_KEY_ELEMENT_SIZE) != EOK) {
        goto SIGN_INIT_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE, key_size,
        sign_start_info->cipher_key.cryptokeyelementvalueref, key_size) != EOK) {
        goto SIGN_INIT_Ex_Handle;
    }

    /* auth_size + 16 */
    if (memmove_s(*buffer_local + HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE + key_size, HSM_IV_SIZE,
        tmp, HSM_IV_SIZE) != EOK) {
        goto SIGN_INIT_Ex_Handle;
    }

    /* auth_size */
    if (memmove_s(*buffer_local + hsm_sign_head_size + key_size, auth_size,
        sign_start_info->cipherkey_auth, auth_size) != EOK) {
        goto SIGN_INIT_Ex_Handle;
    }

    /* promsg_size */
    if (memmove_s(*buffer_local + hsm_sign_head_size + key_size + auth_size, promsg_size,
        sign_start_info->cipherkey_protectmsg, promsg_size) != EOK) {
        goto SIGN_INIT_Ex_Handle;
    }

    /* salt_size */
    if (memmove_s(*buffer_local + hsm_sign_head_size + key_size + auth_size + promsg_size, HSM_SALT_SIZE,
        &salt_size, HSM_SALT_SIZE) != EOK) {
        goto SIGN_INIT_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

SIGN_INIT_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result verify_init_para_check(HSM_VERIFY_START_INFO *verify_start_info)
{
    uint32_t key_size;
    uint32_t auth_size;
    uint32_t sign_size;

    if ((verify_start_info == NULL) || (verify_start_info->cipherkey_auth == NULL) ||
        (verify_start_info->sign == NULL)) {
        return TEE_ERROR_NO_DATA;
    }
    key_size = verify_start_info->cipher_key.cryptokeyelementsize;
    auth_size = verify_start_info->cipherkey_authsize;
    sign_size = verify_start_info->sign_size;

    if ((verify_start_info->cipherkey_protectmsg == NULL) ||
        (verify_start_info->cipher_key.cryptokeyelementvalueref == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((verify_start_info->session_handle == NULL) || (verify_start_info->max_chunk_size == NULL) ||
        (verify_start_info->chunk_block_size == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((key_size > HSM_ASYMKEY_MAX_SIZE) || (auth_size > HSM_AUTH_MAX_SIZE) || (sign_size > HSM_SIGN_MAX_SIZE)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

static TEE_Result verify_init_data_move(uint8_t *buffer_local, HSM_VERIFY_START_INFO *verify_start_info)
{
    uint32_t buffer_offset;
    uint32_t salt_size = HSM_SIGN_VER_SALT_LEN;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    if (memmove_s(buffer_local, HSM_ALG_SIZE, &verify_start_info->alg_id, HSM_ALG_SIZE) != EOK) {
        return TEE_FAIL;
    }

    /* key_size + 32 */
    if (memmove_s(buffer_local + HSM_ALG_SIZE, HSM_KEY_ELEMENT_SIZE,
        &verify_start_info->cipher_key, HSM_KEY_ELEMENT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset = HSM_ALG_SIZE + HSM_KEY_ELEMENT_SIZE;

    if (memmove_s(buffer_local + buffer_offset, verify_start_info->cipher_key.cryptokeyelementsize,
        verify_start_info->cipher_key.cryptokeyelementvalueref,
        verify_start_info->cipher_key.cryptokeyelementsize) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += verify_start_info->cipher_key.cryptokeyelementsize;

    /* auth_size + 16 */
    if (memmove_s(buffer_local + buffer_offset, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_IV_SIZE;

    /* auth_size */
    if (memmove_s(buffer_local + buffer_offset, verify_start_info->cipherkey_authsize,
        verify_start_info->cipherkey_auth, verify_start_info->cipherkey_authsize) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += verify_start_info->cipherkey_authsize;

    /* promsg_size */
    if (memmove_s(buffer_local + buffer_offset, verify_start_info->cipherkey_authsize + HSM_KEY_PROTECT_SIZE,
        verify_start_info->cipherkey_protectmsg, verify_start_info->cipherkey_authsize + HSM_KEY_PROTECT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += (verify_start_info->cipherkey_authsize + HSM_KEY_PROTECT_SIZE);

    /* salt_size */
    if (memmove_s(buffer_local + buffer_offset, HSM_SALT_SIZE, &salt_size, HSM_SALT_SIZE) != EOK) {
        return TEE_FAIL;
    }

    buffer_offset += HSM_SALT_SIZE;

    if (memmove_s(buffer_local + buffer_offset, verify_start_info->sign_size,
        verify_start_info->sign, verify_start_info->sign_size) != EOK) {
        return TEE_FAIL;
    }

    return TEE_SUCCESS;
}

TEE_Result verify_init_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_VERIFY_START_INFO *verify_start_info)
{
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint32_t ret;

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = verify_init_data_move(*buffer_local, verify_start_info);
    if (ret != TEE_SUCCESS) {
        goto VERIFY_INIT_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

VERIFY_INIT_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}
