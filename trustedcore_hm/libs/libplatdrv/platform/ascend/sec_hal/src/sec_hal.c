/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: sec hal functions
* Author: shenhan
* Create: 2019/12/30
*/
#include "stdlib.h"
#include "drv_module.h"
#include "sre_access_control.h"
#include "drv_mem.h"
#include "tee_log.h"
#include "crypto_driver_adaptor.h"

#include "securec.h"

#include "driver_common.h"
#include "sec_a_hal.h"

static const ctx_size_map_s g_ctx_size_map[] = {
    {CRYPTO_TYPE_DIGEST_SHA1,   sizeof(hash_ctx_t)},
    {CRYPTO_TYPE_DIGEST_SHA224, sizeof(hash_ctx_t)},
    {CRYPTO_TYPE_DIGEST_SHA256, sizeof(hash_ctx_t)},
    {CRYPTO_TYPE_DIGEST_SHA384, sizeof(hash_ctx_t)},
    {CRYPTO_TYPE_DIGEST_SHA512, sizeof(hash_ctx_t)},
    {CRYPTO_TYPE_DIGEST_SM3,    sizeof(hash_ctx_t)},
    {CRYPTO_TYPE_HMAC_SHA1,     sizeof(hmac_ctx_t)},
    {CRYPTO_TYPE_HMAC_SHA224,   sizeof(hmac_ctx_t)},
    {CRYPTO_TYPE_HMAC_SHA256,   sizeof(hmac_ctx_t)},
    {CRYPTO_TYPE_HMAC_SHA384,   sizeof(hmac_ctx_t)},
    {CRYPTO_TYPE_HMAC_SHA512,   sizeof(hmac_ctx_t)},
    {CRYPTO_TYPE_HMAC_SM3,      sizeof(hmac_ctx_t)},
    {CRYPTO_TYPE_AES_ECB_NOPAD, sizeof(cipher_ctx_t)},
    {CRYPTO_TYPE_AES_CBC_NOPAD, sizeof(cipher_ctx_t)},
    {CRYPTO_TYPE_AES_ECB_PKCS5, sizeof(cipher_ctx_t)},
    {CRYPTO_TYPE_AES_CBC_PKCS5, sizeof(cipher_ctx_t)},
    {CRYPTO_TYPE_AES_CTR,       sizeof(cipher_ctx_t)},
    {CRYPTO_TYPE_AES_OFB,       sizeof(cipher_ctx_t)},
    {CRYPTO_TYPE_SM4_CBC,       sizeof(cipher_ctx_t)},
    {CRYPTO_TYPE_SM4_CTR,       sizeof(cipher_ctx_t)},
    {CRYPTO_TYPE_SM4_OFB,       sizeof(cipher_ctx_t)},
    {CRYPTO_TYPE_AES_GCM,       sizeof(ae_ctx_t)},
};

static const hash_option_map_s g_hash_option_map[] = {
    {CRYPTO_TYPE_DIGEST_SHA1,   SHA1,   SHA1_OUT_WLEN},
    {CRYPTO_TYPE_DIGEST_SHA224, SHA224, SHA224_OUT_WLEN},
    {CRYPTO_TYPE_DIGEST_SHA256, SHA256, SHA256_OUT_WLEN},
    {CRYPTO_TYPE_DIGEST_SHA384, SHA384, SHA384_OUT_WLEN},
    {CRYPTO_TYPE_DIGEST_SHA512, SHA512, SHA512_OUT_WLEN},
    {CRYPTO_TYPE_DIGEST_SM3,    SM3,    SM3_OUT_WLEN},
};

static const hmac_option_map_s g_hmac_option_map[] = {
    {CRYPTO_TYPE_HMAC_SHA1,     HMAC_SHA1, SHA1_OUT_WLEN},
    {CRYPTO_TYPE_HMAC_SHA224,   HMAC_SHA224, SHA224_OUT_WLEN},
    {CRYPTO_TYPE_HMAC_SHA256,   HMAC_SHA256, SHA256_OUT_WLEN},
    {CRYPTO_TYPE_HMAC_SHA384,   HMAC_SHA384, SHA384_OUT_WLEN},
    {CRYPTO_TYPE_HMAC_SHA512,   HMAC_SHA512, SHA512_OUT_WLEN},
    {CRYPTO_TYPE_HMAC_SM3,      HMAC_SM3, SM3_OUT_WLEN},
};

STATIC int get_ctx_size(uint32_t alg_type)
{
    uint32_t i;

    for (i = 0; i < (sizeof(g_ctx_size_map) / sizeof(ctx_size_map_s)); i++) {
        if (alg_type == g_ctx_size_map[i].alg_type) {
            return g_ctx_size_map[i].ctx_size;
        }
    }

    return CRYPTO_NOT_SUPPORTED;
}

STATIC int get_driver_ability(void)
{
    return DRIVER_PADDING | DRIVER_CACHE;
}

STATIC int hash_option_select(uint32_t alg_type, uint32_t *hash_option, uint32_t *outlen)
{
    uint32_t i;

    for (i = 0; i < (sizeof(g_hash_option_map) / sizeof(hash_option_map_s)); i++) {
        if (alg_type == g_hash_option_map[i].alg_type) {
            *hash_option = g_hash_option_map[i].option;
            *outlen = g_hash_option_map[i].out_wlen;
            return CRYPTO_SUCCESS;
        }
    }

    return CRYPTO_NOT_SUPPORTED;
}

STATIC int hash_init_a(void *ctx, uint32_t alg_type)
{
    uint32_t ret;
    hash_ctx_t *hash_ctx = (hash_ctx_t*)ctx;

    ret = hash_option_select(alg_type, &hash_ctx->alg_type, &hash_ctx->outlen);
    if (ret != CRYPTO_SUCCESS) {
        return CRYPTO_NOT_SUPPORTED;
    }

    hash_ctx->flag = IS_FIRST_BLOCK;
    hash_ctx->buf_offset = 0;
    hash_ctx->total_len[0] = 0;
    hash_ctx->total_len[1] = 0;
    return CRYPTO_SUCCESS;
}

STATIC int hash_init(void *ctx, uint32_t alg_type)
{
    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    return hash_init_a(ctx, alg_type);
}

STATIC int hash_block_crypto(hash_ctx_t *sha_ctx, struct memref_t *block_in)
{
    SEC_HASH_INFO_S hash_info = {0};
    sec_bd_t bd;
    uint32_t ret;

    hash_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
    hash_info.data_addr = block_in->buffer;
    hash_info.data_len = block_in->size;
    hash_info.hash_type = sha_ctx->alg_type;
    hash_info.mac_len = sha_ctx->outlen;
    hash_info.result_addr = (uint64_t)(uintptr_t)sha_ctx->iv;

    if (sha_ctx->flag == IS_FIRST_BLOCK) {
        sha_ctx->flag = IS_NOT_FIRST_BLOCK;
        ret = sec_hash_init(&hash_info);
    } else {
        hash_info.iv_addr = (uint64_t)(uintptr_t)sha_ctx->iv;
        ret = sec_hash_update(&hash_info);
    }

    if (ret != SEC_SUCCESS) {
        return CRYPTO_CIPHERTEXT_INVALID;
    }

    return CRYPTO_SUCCESS;
}

STATIC int hash_update_cal(uint32_t *current_len, uint32_t *last_len, uint32_t *data_offset,
    const struct memref_t *data_in, hash_ctx_t *sha_ctx)
{
    struct memref_t block_in;
    uint32_t copy_len;
    uint8_t *space = NULL;
    space = (uint8_t *)malloc_coherent(SEC_PAGE_SIZE);
    if (space == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    while (*current_len >= (SEC_PAGE_SIZE + SHA_BLOCK_LEN)) {
        if (memcpy_s((void *)space, SEC_PAGE_SIZE, (void *)(uintptr_t)(data_in->buffer + *data_offset),
            SEC_PAGE_SIZE) != 0) {
            goto HASH_UPDATE_Ex_Handle;
        }

        block_in.buffer = (uint64_t)(uintptr_t)space;
        block_in.size = SEC_PAGE_SIZE;
        if (hash_block_crypto(sha_ctx, &block_in) != CRYPTO_SUCCESS) {
            goto HASH_UPDATE_Ex_Handle;
        }

        *current_len -= SEC_PAGE_SIZE;
        *data_offset += SEC_PAGE_SIZE;
    }

    copy_len = *current_len & BLOCK_LEN_MASK;
    *last_len = *current_len - copy_len;
    if (copy_len != 0) {
        if (memcpy_s((void *)space, SEC_PAGE_SIZE, (void *)(uintptr_t)(data_in->buffer + *data_offset),
            copy_len) != 0) {
            goto HASH_UPDATE_Ex_Handle;
        }

        block_in.buffer = (uint64_t)(uintptr_t)space;
        block_in.size = copy_len;
        if (hash_block_crypto(sha_ctx, &block_in) != CRYPTO_SUCCESS) {
            goto HASH_UPDATE_Ex_Handle;
        }

        *data_offset += copy_len;
    }
    free(space);
    space = NULL;
    return CRYPTO_SUCCESS;

HASH_UPDATE_Ex_Handle:
    free(space);
    space = NULL;
    return CRYPTO_BAD_PARAMETERS;
}

STATIC int hash_update_a(void *ctx, const struct memref_t *data_in)
{
    uint32_t data_offset = 0;
    struct memref_t block_in;
    uint32_t current_len, last_len, copy_len;
    hash_ctx_t *sha_ctx = (hash_ctx_t *)(ctx);
    current_len = sha_ctx->buf_offset + data_in->size;

    sha_ctx->total_len[0] += data_in->size >> SHIFT29;
    sha_ctx->total_len[1] += data_in->size << SHIFT3;
    if (sha_ctx->total_len[1] < (data_in->size << SHIFT3)) {
        sha_ctx->total_len[0]++;
    }
    if (current_len > SHA_BLOCK_LEN) {
        if (sha_ctx->buf_offset != 0) {
            copy_len = SHA_BLOCK_LEN - sha_ctx->buf_offset;
            if ((copy_len != 0) && (memcpy_s((void *)(sha_ctx->buf + sha_ctx->buf_offset), sizeof(sha_ctx->buf)
                - sha_ctx->buf_offset, (const void *)(uintptr_t)(data_in->buffer + data_offset), copy_len) != 0)) {
                goto HASH_UPDATE_Ex_Handle;
            }
            block_in.buffer = (uint64_t)(uintptr_t)(sha_ctx->buf);
            block_in.size = SHA_BLOCK_LEN;
            if (hash_block_crypto(sha_ctx, &block_in) != CRYPTO_SUCCESS) {
                goto HASH_UPDATE_Ex_Handle;
            }
            sha_ctx->buf_offset = 0;
            current_len = current_len - SHA_BLOCK_LEN;
            data_offset = copy_len;
        }
        if (hash_update_cal(&current_len, &last_len, &data_offset, data_in, sha_ctx) != CRYPTO_SUCCESS) {
            goto HASH_UPDATE_Ex_Handle;
        }
    } else {
        last_len = data_in->size;
    }

    if ((last_len != 0) && (memcpy_s((void *)(sha_ctx->buf + sha_ctx->buf_offset),
        sizeof(sha_ctx->buf) - sha_ctx->buf_offset, (const void *)(uintptr_t)(data_in->buffer + data_offset),
        last_len) != 0)) {
        goto HASH_UPDATE_Ex_Handle;
    }
    sha_ctx->buf_offset += last_len;
    return CRYPTO_SUCCESS;

HASH_UPDATE_Ex_Handle:
    return CRYPTO_BAD_PARAMETERS;
}

STATIC int hash_update(void *ctx, const struct memref_t *data_in)
{
    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    return hash_update_a(ctx, data_in);
}

STATIC int hash_dofinal_a(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    uint32_t ret = 0;
    SEC_HASH_INFO_S hash_info;
    hash_ctx_t *sha_ctx = (hash_ctx_t*)ctx;
    sec_bd_t bd;

    if ((data_out == NULL) || (data_out->buffer == 0)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if ((data_in != NULL) && (data_in->buffer != 0)) {
        ret = hash_update_a(ctx, data_in);
        if (ret != CRYPTO_SUCCESS) {
            goto HASH_FINAL_Ex_Handle;
        }
    }

    if (sha_ctx->flag == IS_FIRST_BLOCK) {
        hash_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
        hash_info.data_addr = (uint64_t)(uintptr_t)sha_ctx->buf;
        hash_info.data_len = sha_ctx->buf_offset;
        hash_info.hash_type = sha_ctx->alg_type;
        hash_info.mac_len = sha_ctx->outlen;
        hash_info.result_addr = (uint64_t)(uintptr_t)sha_ctx->data_out_buf;

        ret = sec_hash_simple(&hash_info);
        if (ret != SEC_SUCCESS) {
            goto HASH_FINAL_Ex_Handle;
        }
    } else {
        hash_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
        hash_info.data_addr = (uint64_t)(uintptr_t)sha_ctx->buf;
        hash_info.iv_addr = (uint64_t)(uintptr_t)sha_ctx->iv;
        hash_info.data_len = sha_ctx->buf_offset;
        hash_info.long_data_len_l = sha_ctx->total_len[1];
        hash_info.long_data_len_h = sha_ctx->total_len[0];
        hash_info.hash_type = sha_ctx->alg_type;
        hash_info.mac_len = sha_ctx->outlen;
        hash_info.result_addr = (uint64_t)(uintptr_t)sha_ctx->data_out_buf;

        ret = sec_hash_final(&hash_info);
        if (ret != SEC_SUCCESS) {
            goto HASH_FINAL_Ex_Handle;
        }
    }

    data_out->size = sha_ctx->outlen << SHIFT2;
    if (memcpy_s((void *)(data_out->buffer), SHA_BLOCK_LEN,
        (const void *)(uintptr_t)(sha_ctx->data_out_buf), data_out->size) != 0) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    return CRYPTO_SUCCESS;

HASH_FINAL_Ex_Handle:
    return CRYPTO_BAD_PARAMETERS;
}

STATIC int hash_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    return hash_dofinal_a(ctx, data_in, data_out);
}

STATIC int hash_simple(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    uint32_t ret;
    hash_ctx_t hash_ctx;

    ret = hash_init_a(&hash_ctx, alg_type);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    ret = hash_dofinal_a(&hash_ctx, data_in, data_out);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    return CRYPTO_SUCCESS;
}

STATIC int hmac_option_select(uint32_t alg_type, uint32_t *hmac_option, uint32_t *outlen)
{
    uint32_t i;

    for (i = 0; i < (sizeof(g_hmac_option_map) / sizeof(hmac_option_map_s)); i++) {
        if (alg_type == g_hmac_option_map[i].alg_type) {
            *hmac_option = g_hmac_option_map[i].option;
            *outlen = g_hmac_option_map[i].out_wlen;
            return CRYPTO_SUCCESS;
        }
    }

    return CRYPTO_NOT_SUPPORTED;
}

STATIC int hmac_init_para_check(void *ctx, const struct symmerit_key_t *c_key)
{
    hmac_ctx_t *hmac_ctx = (hmac_ctx_t*)ctx;

    if ((c_key->key_buffer == 0) || (c_key->key_size == 0)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    switch (c_key->key_type) {
        case CRYPTO_KEYTYPE_RPMB:
            if (sec_km_key_req(KEY_WRAPK1) != SEC_SUCCESS) {
                tloge(" SEC Request KM WRAK1 Failed");
                return CRYPTO_BAD_STATE;
            }

            hmac_ctx->key_type = WRAPK1;
            if (c_key->key_size != RPMB_WRAPPING_KEY_SIZE) {
                return CRYPTO_BAD_PARAMETERS;
            }
            hmac_ctx->key_size = RPMB_KEY_SIZE >> SHIFT2;
            break;
        case CRYPTO_KEYTYPE_USER:
            hmac_ctx->key_type = OUT_KEY;
            if ((c_key->key_size > SHA_KEY_MAX_BLEN) || ((c_key->key_size & BYTE2WORD_MASK) != 0)) {
                return CRYPTO_BAD_PARAMETERS;
            }
            hmac_ctx->key_size = c_key->key_size >> SHIFT2;
            break;
        default:
            return CRYPTO_NOT_SUPPORTED;
    }

    return CRYPTO_SUCCESS;
}

STATIC int hmac_init_a(uint32_t alg_type, void *ctx, const struct symmerit_key_t *c_key)
{
    uint32_t ret;
    hmac_ctx_t *hmac_ctx = (hmac_ctx_t*)ctx;

    ret = hmac_init_para_check(ctx, c_key);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    ret = hmac_option_select(alg_type, &hmac_ctx->alg_type, &hmac_ctx->outlen);
    if (ret != CRYPTO_SUCCESS) {
        return CRYPTO_NOT_SUPPORTED;
    }

    hmac_ctx->flag = IS_FIRST_BLOCK;
    hmac_ctx->buf_offset = 0;
    hmac_ctx->total_len[0] = 0;
    hmac_ctx->total_len[1] = 0;

    if (memcpy_s((void *)(hmac_ctx->c_key), SHA_KEY_MAX_BLEN,
        (const void *)(uintptr_t)(c_key->key_buffer), c_key->key_size) != 0) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    return CRYPTO_SUCCESS;
}

STATIC int hmac_init(uint32_t alg_type, void *ctx, const struct symmerit_key_t *c_key)
{
    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    return hmac_init_a(alg_type, ctx, c_key);
}

STATIC int hmac_block_crypto(hmac_ctx_t *sha_ctx, struct memref_t *block_in)
{
    SEC_HMAC_INFO_S hmac_info = {0};
    sec_bd_t bd;
    uint32_t ret;

    hmac_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
    hmac_info.data_addr = block_in->buffer;
    hmac_info.data_len = block_in->size;
    hmac_info.key_addr = (uint64_t)(uintptr_t)sha_ctx->c_key;
    hmac_info.key_len = sha_ctx->key_size;
    hmac_info.hmac_type = sha_ctx->alg_type;
    hmac_info.mac_len = sha_ctx->outlen;
    hmac_info.key_type = sha_ctx->key_type;
    hmac_info.result_addr = (uint64_t)(uintptr_t)sha_ctx->iv;

    if (sha_ctx->flag == IS_FIRST_BLOCK) {
        sha_ctx->flag = IS_NOT_FIRST_BLOCK;
        ret = sec_hmac_init(&hmac_info);
    } else {
        hmac_info.iv_addr = (uint32_t)(uintptr_t)sha_ctx->iv;
        ret = sec_hmac_update(&hmac_info);
    }

    if (ret != SEC_SUCCESS) {
        return CRYPTO_CIPHERTEXT_INVALID;
    }

    return CRYPTO_SUCCESS;
}

STATIC int hmac_update_cal(uint32_t *current_len, uint32_t *last_len, uint32_t *data_offset,
    const struct memref_t *data_in, hmac_ctx_t *sha_ctx)
{
    struct memref_t block_in;
    uint32_t copy_len;
    uint8_t *space = NULL;
    space = (uint8_t *)malloc_coherent(SEC_PAGE_SIZE);
    if (space == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    while (*current_len >= (SEC_PAGE_SIZE + SHA_BLOCK_LEN)) {
        if (memcpy_s((void *)space, SEC_PAGE_SIZE, (void *)(uintptr_t)(data_in->buffer + *data_offset),
            SEC_PAGE_SIZE) != 0) {
            goto HMAC_UPDATE_Ex_Handle;
        }

        block_in.buffer = (uint64_t)(uintptr_t)space;
        block_in.size = SEC_PAGE_SIZE;
        if (hmac_block_crypto(sha_ctx, &block_in) != CRYPTO_SUCCESS) {
            goto HMAC_UPDATE_Ex_Handle;
        }

        *current_len -= SEC_PAGE_SIZE;
        *data_offset += SEC_PAGE_SIZE;
    }

    copy_len = *current_len & BLOCK_LEN_MASK;
    *last_len = *current_len - copy_len;
    if (copy_len != 0) {
        if (memcpy_s((void *)space, SEC_PAGE_SIZE, (void *)(uintptr_t)(data_in->buffer + *data_offset),
            copy_len) != 0) {
            goto HMAC_UPDATE_Ex_Handle;
        }

        block_in.buffer = (uint64_t)(uintptr_t)space;
        block_in.size = copy_len;
        if (hmac_block_crypto(sha_ctx, &block_in) != CRYPTO_SUCCESS) {
            goto HMAC_UPDATE_Ex_Handle;
        }
        *data_offset += copy_len;
    }

    free(space);
    space = NULL;
    return CRYPTO_SUCCESS;

HMAC_UPDATE_Ex_Handle:
    free(space);
    space = NULL;
    return CRYPTO_BAD_PARAMETERS;
}

STATIC int hmac_update_a(void *ctx, const struct memref_t *data_in)
{
    hmac_ctx_t *sha_ctx = (hmac_ctx_t*)ctx;
    struct memref_t block_in;
    uint32_t copy_len, current_len, last_len;
    uint32_t data_offset = 0;
    current_len = sha_ctx->buf_offset + data_in->size;

    sha_ctx->total_len[0] += data_in->size >> SHIFT29;
    sha_ctx->total_len[1] += data_in->size << SHIFT3;
    if (sha_ctx->total_len[1] < (data_in->size << SHIFT3)) {
        sha_ctx->total_len[0]++;
    }
    if (current_len > SHA_BLOCK_LEN) {
        if (sha_ctx->buf_offset != 0) {
            copy_len = SHA_BLOCK_LEN - sha_ctx->buf_offset;
            if ((copy_len != 0) && (memcpy_s((void *)(sha_ctx->buf + sha_ctx->buf_offset), sizeof(sha_ctx->buf)
                - sha_ctx->buf_offset, (void *)(uintptr_t)(data_in->buffer + data_offset), copy_len) != 0)) {
                goto HMAC_UPDATE_Ex_Handle;
            }
            block_in.buffer = (uint64_t)(uintptr_t)(sha_ctx->buf);
            block_in.size = SHA_BLOCK_LEN;
            if (hmac_block_crypto(sha_ctx, &block_in) != CRYPTO_SUCCESS) {
                goto HMAC_UPDATE_Ex_Handle;
            }
            sha_ctx->buf_offset = 0;
            current_len = current_len - SHA_BLOCK_LEN;
            data_offset = copy_len;
        }
        if (hmac_update_cal(&current_len, &last_len, &data_offset, data_in, sha_ctx) != CRYPTO_SUCCESS) {
            goto HMAC_UPDATE_Ex_Handle;
        }
    } else {
        last_len = data_in->size;
    }

    if ((last_len != 0) && (memcpy_s((void *)(sha_ctx->buf + sha_ctx->buf_offset),
        sizeof(sha_ctx->buf) - sha_ctx->buf_offset, (void *)(uintptr_t)(data_in->buffer + data_offset),
        last_len) != 0)) {
        goto HMAC_UPDATE_Ex_Handle;
    }
    sha_ctx->buf_offset += last_len;
    return CRYPTO_SUCCESS;

HMAC_UPDATE_Ex_Handle:
    return CRYPTO_BAD_PARAMETERS;
}

STATIC int hmac_update(void *ctx, const struct memref_t *data_in)
{
    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    return hmac_update_a(ctx, data_in);
}

STATIC int hmac_dofinal_a(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    uint32_t ret = 0;
    SEC_HMAC_INFO_S hmac_info = {0};
    hmac_ctx_t *sha_ctx = (hmac_ctx_t*)ctx;
    sec_bd_t bd;

    if ((data_out == NULL) || (data_out->buffer == 0)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if ((data_in != NULL) && (data_in->buffer != 0)) {
        ret = hmac_update_a(ctx, data_in);
        if (ret != CRYPTO_SUCCESS) {
            goto HMAC_FINAL_Ex_Handle;
        }
    }
    hmac_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
    hmac_info.data_addr = (uint64_t)(uintptr_t)sha_ctx->buf;
    hmac_info.hmac_type = sha_ctx->alg_type;
    hmac_info.mac_len = sha_ctx->outlen;
    hmac_info.result_addr = (uint64_t)(uintptr_t)sha_ctx->data_out_buf;
    hmac_info.key_type = sha_ctx->key_type;
    hmac_info.data_len = sha_ctx->buf_offset;
    hmac_info.key_addr = (uint64_t)(uintptr_t)sha_ctx->c_key;
    hmac_info.key_len = sha_ctx->key_size;

    if (sha_ctx->flag == IS_FIRST_BLOCK) {
        ret = sec_hmac_simple(&hmac_info);
        if (ret != SEC_SUCCESS) {
            goto HMAC_FINAL_Ex_Handle;
        }
    } else {
        hmac_info.iv_addr = (uint64_t)(uintptr_t)sha_ctx->iv;
        hmac_info.long_data_len_l = sha_ctx->total_len[1];
        hmac_info.long_data_len_h = sha_ctx->total_len[0];
        ret = sec_hmac_final(&hmac_info);
        if (ret != SEC_SUCCESS) {
            goto HMAC_FINAL_Ex_Handle;
        }
    }
    data_out->size = sha_ctx->outlen << SHIFT2;
    if (memcpy_s((void *)(uintptr_t)data_out->buffer, SHA_BLOCK_LEN,
        (void *)sha_ctx->data_out_buf, data_out->size) != 0) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    return CRYPTO_SUCCESS;

HMAC_FINAL_Ex_Handle:
    return CRYPTO_BAD_PARAMETERS;
}

STATIC int hmac_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    return hmac_dofinal_a(ctx, data_in, data_out);
}

STATIC int hmac(uint32_t alg_type, const struct symmerit_key_t *c_key, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    uint32_t ret;
    hmac_ctx_t sha_ctx;

    ret = hmac_init_a(alg_type, &sha_ctx, c_key);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    ret = hmac_dofinal_a(&sha_ctx, data_in, data_out);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    return CRYPTO_SUCCESS;
}

static const cipher_option_map_s g_cipher_option_map[] = {
    {CRYPTO_TYPE_AES_ECB_NOPAD, SEC_AES, AES_ECB, NO_PADDING},
    {CRYPTO_TYPE_AES_CBC_NOPAD, SEC_AES, AES_CBC, NO_PADDING},
    {CRYPTO_TYPE_AES_ECB_PKCS5, SEC_AES, AES_ECB, PKCS5_PADDING},
    {CRYPTO_TYPE_AES_CBC_PKCS5, SEC_AES, AES_CBC, PKCS5_PADDING},
    {CRYPTO_TYPE_AES_CTR,       SEC_AES, AES_CTR, NOT_NEED_PADDING},
    {CRYPTO_TYPE_AES_XTS,       SEC_AES, AES_XTS, NOT_NEED_PADDING},
    {CRYPTO_TYPE_AES_OFB,       SEC_AES, AES_OFB, NOT_NEED_PADDING},
    {CRYPTO_TYPE_SM4_CBC,       SEC_SM4, AES_CBC, NO_PADDING},
    {CRYPTO_TYPE_SM4_CTR,       SEC_SM4, AES_CTR, NOT_NEED_PADDING},
    {CRYPTO_TYPE_SM4_XTS,       SEC_SM4, AES_XTS, NOT_NEED_PADDING},
    {CRYPTO_TYPE_SM4_OFB,       SEC_SM4, AES_OFB, NOT_NEED_PADDING},
};

STATIC int cipher_option_select(uint32_t alg_type, uint32_t *mode, uint32_t *option, uint32_t *padding_mode)
{
    uint32_t i;

    for (i = 0; i < (sizeof(g_cipher_option_map) / sizeof(cipher_option_map_s)); i++) {
        if (alg_type == g_cipher_option_map[i].alg_type) {
            *option = g_cipher_option_map[i].option;
            *mode = g_cipher_option_map[i].mode;
            *padding_mode = g_cipher_option_map[i].padding_mode;
            return CRYPTO_SUCCESS;
        }
    }

    return CRYPTO_NOT_SUPPORTED;
}

static void cipher_set_padding(uint8_t *buffer, uint32_t tail_len, uint32_t size)
{
    uint32_t i;

    for (i = 0; i < tail_len; i++) {
        buffer[size + i] = tail_len;
    }
}

STATIC uint32_t cipher_remove_padding(uint8_t *buffer, uint32_t *size)
{
    uint32_t i;

    if (buffer[*size - 1] > CIPHER_BLOCK_BLEN) {
        return CRYPTO_BAD_PARAMETERS;
    }

    for (i = *size - buffer[*size - 1]; i < *size; i++) {
        if (buffer[i] != buffer[*size - 1]) {
            return CRYPTO_BAD_PARAMETERS;
        }
    }
    *size = *size - buffer[*size - 1];

    return CRYPTO_SUCCESS;
}

STATIC int cipher_init_a(uint32_t alg_type, void *ctx, uint32_t direction, const struct symmerit_key_t *c_key,
    const struct memref_t *iv)
{
    uint32_t ret;
    cipher_ctx_t *cipher_ctx = (cipher_ctx_t*)ctx;

    ret = cipher_option_select(alg_type, &cipher_ctx->mode, &cipher_ctx->option, &cipher_ctx->padding_mode);
    if (ret != CRYPTO_SUCCESS) {
        return CRYPTO_NOT_SUPPORTED;
    }

    if (cipher_ctx->mode != AES_ECB) {
        if (iv->size != CIPHER_IV_LEN) {
            return CRYPTO_BAD_PARAMETERS;
        }

        if (memcpy_s((void *)cipher_ctx->iv, CIPHER_IV_LEN, (void *)(uintptr_t)iv->buffer, iv->size) != 0) {
            return CRYPTO_SHORT_BUFFER;
        }
    }

    if (memcpy_s((void *)cipher_ctx->c_key, CIPHER_KEY_MAX_LEN,
        (void *)(uintptr_t)c_key->key_buffer, c_key->key_size) != 0) {
        return CRYPTO_SHORT_BUFFER;
    }

    if ((direction != ENC_MODE) && (direction != DEC_MODE)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    cipher_ctx->key_size = (c_key->key_size - CIPHER_UNIT_LEN) >> SHIFT3;
    cipher_ctx->direct = direction + 1;
    cipher_ctx->buf_offset = 0;

    return CRYPTO_SUCCESS;
}

STATIC int cipher_init(uint32_t alg_type, void *ctx, uint32_t direction,
                       const struct symmerit_key_t *c_key, const struct memref_t *iv)
{
    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    return cipher_init_a(alg_type, ctx, direction, c_key, iv);
}

STATIC void word2byter(uint32_t *W, uint8_t *B, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        B[(W2B_SIZE * i) + W2B_OFF0] = (uint8_t)((W[i] >> SHIFT24) & BYTE_MASK);
        B[(W2B_SIZE * i) + W2B_OFF1] = (uint8_t)((W[i] >> SHIFT16) & BYTE_MASK);
        B[(W2B_SIZE * i) + W2B_OFF2] = (uint8_t)((W[i] >> SHIFT8) & BYTE_MASK);
        B[(W2B_SIZE * i) + W2B_OFF3] = (uint8_t)((W[i] >> SHIFT0) & BYTE_MASK);
    }
}

STATIC void byte2wordr(uint32_t *W, uint8_t *B, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        W[i] = (((uint32_t)B[(W2B_SIZE * i) + W2B_OFF0]) << SHIFT24) |
               (((uint32_t)B[(W2B_SIZE * i) + W2B_OFF1]) << SHIFT16) |
               (((uint32_t)B[(W2B_SIZE * i) + W2B_OFF2]) << SHIFT8) |
               (((uint32_t)B[(W2B_SIZE * i) + W2B_OFF3]) << SHIFT0);
    }
}

STATIC void crypto_mem_xor(uint8_t *scr1, uint8_t *scr2, uint32_t len, uint8_t *dst)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        dst[i] = scr1[i] ^ scr2[i];
    }
}

STATIC int cipher_update_iv(uint32_t itr, cipher_ctx_t *cipher_ctx, uint8_t *cipher_in, uint8_t *iv_tmp)
{
    uint32_t counter = 0;

    switch (cipher_ctx->mode) {
        case AES_CTR:
            byte2wordr(&counter, cipher_ctx->iv + AES_CTR_COUNTER_OFFSET, 1);
            counter = counter + itr;
            word2byter(&counter, cipher_ctx->iv + AES_CTR_COUNTER_OFFSET, 1);
            break;
        case AES_CBC:
            if (cipher_ctx->direct == AES_ENC) {
                if (memcpy_s((void *)cipher_ctx->iv, CIPHER_UNIT_LEN,
                    (void *)(cipher_in + (CIPHER_UNIT_LEN * (itr - 1))), CIPHER_UNIT_LEN) != 0) {
                    return CRYPTO_ERROR_SECURITY;
                }
            } else {
                if (memcpy_s((void *)cipher_ctx->iv, CIPHER_UNIT_LEN,
                    (void *)iv_tmp, CIPHER_UNIT_LEN) != 0) {
                    return CRYPTO_ERROR_SECURITY;
                }
            }
            break;
        case AES_OFB:
            if (itr != 0) {
                crypto_mem_xor(cipher_in + (CIPHER_UNIT_LEN * (itr - 1)), iv_tmp, CIPHER_UNIT_LEN, cipher_ctx->iv);
            }
            break;
        case AES_ECB:
            break;
        default:
            return CRYPTO_NOT_SUPPORTED;
    }

    return CRYPTO_SUCCESS;
}

STATIC int cipher_block_crypto(cipher_ctx_t *cipher_ctx, struct memref_t *block_in, struct memref_t *block_out)
{
    SEC_AES_INFO_S cipher_info = {0};
    sec_bd_t bd;
    uint32_t ret;
    uint32_t itr = block_in->size >> SHIFT4;
    uint8_t iv_tmp[CIPHER_IV_LEN] = {0};

    block_out->size = block_in->size;
    if (block_in->size == 0) {
        return CRYPTO_SUCCESS;
    }

    if (itr != 0) {
        if (memcpy_s((void *)iv_tmp, CIPHER_IV_LEN,
            (void *)(block_in->buffer + CIPHER_UNIT_LEN * (itr - 1)), CIPHER_UNIT_LEN) != 0) {
            return CRYPTO_ERROR_SECURITY;
        }
    }

    cipher_info.aes_enc = cipher_ctx->direct;
    cipher_info.aes_key_len = cipher_ctx->key_size;
    cipher_info.aes_mode = cipher_ctx->mode;
    cipher_info.cipher_mode = cipher_ctx->option;
    cipher_info.data_addr = block_in->buffer;
    cipher_info.data_len = block_in->size;
    cipher_info.iv_addr = (uint64_t)(uintptr_t)cipher_ctx->iv;
    cipher_info.key_addr = (uint64_t)(uintptr_t)cipher_ctx->c_key;
    cipher_info.result_addr = block_in->buffer;
    cipher_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;

    ret = sec_aes_sm4(&cipher_info);
    if (ret != SEC_SUCCESS) {
        return CRYPTO_CIPHERTEXT_INVALID;
    }

    ret = cipher_update_iv(itr, cipher_ctx, (uint8_t *)(uintptr_t)block_in->buffer, iv_tmp);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    if (memcpy_s((void *)(uintptr_t)block_out->buffer, block_out->size,
        (void *)(uintptr_t)block_in->buffer, block_in->size) != 0) {
        return CRYPTO_ERROR_SECURITY;
    }

    return CRYPTO_SUCCESS;
}

STATIC int cipher_update_cal(uint32_t *current_len, uint32_t *last_len, uint32_t *data_offset,
    struct memref_t *data_out, const struct memref_t *data_in, cipher_ctx_t *cipher_ctx)
{
    struct memref_t block_in, block_out;
    uint32_t copy_len;
    uint8_t *space = NULL;
    space = (uint8_t *)malloc_coherent(SEC_PAGE_SIZE);
    if (space == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    while (*current_len >= (SEC_PAGE_SIZE + CIPHER_BLOCK_LEN)) {
        if (memcpy_s((void *)space, SEC_PAGE_SIZE,
            (void *)(uintptr_t)(data_in->buffer + *data_offset), SEC_PAGE_SIZE) != 0) {
            goto CIPHER_UPDATE_Ex_Handle;
        }
        block_in.buffer = (uint64_t)(uintptr_t)space;
        block_in.size = SEC_PAGE_SIZE;
        block_out.buffer = data_out->buffer + data_out->size;
        if (cipher_block_crypto(cipher_ctx, &block_in, &block_out) != CRYPTO_SUCCESS) {
            goto CIPHER_UPDATE_Ex_Handle;
        }

        *current_len -= SEC_PAGE_SIZE;
        *data_offset += SEC_PAGE_SIZE;
        data_out->size += SEC_PAGE_SIZE;
    }
    copy_len = *current_len & BLOCK_LEN_MASK;
    *last_len = *current_len - copy_len;
    if (*last_len == 0) {
        copy_len -= CIPHER_BLOCK_LEN;
        *last_len = CIPHER_BLOCK_LEN;
    }
    if (copy_len != 0) {
        if (memcpy_s((void *)space, SEC_PAGE_SIZE, (void *)(uintptr_t)(data_in->buffer + *data_offset),
            copy_len) != 0) {
            goto CIPHER_UPDATE_Ex_Handle;
        }
        block_in.buffer = (uint64_t)(uintptr_t)space;
        block_in.size = copy_len;
        block_out.buffer = data_out->buffer + data_out->size;
        if (cipher_block_crypto(cipher_ctx, &block_in, &block_out) != CRYPTO_SUCCESS) {
            goto CIPHER_UPDATE_Ex_Handle;
        }
        data_out->size += copy_len;
        *data_offset += copy_len;
    }
    free(space);
    space = NULL;
    return CRYPTO_SUCCESS;
CIPHER_UPDATE_Ex_Handle:
    free(space);
    space = NULL;
    return CRYPTO_ERROR_SECURITY;
}

STATIC int cipher_update_a(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    cipher_ctx_t *cipher_ctx = (cipher_ctx_t *)ctx;
    struct memref_t block_in, block_out;
    uint32_t copy_len, current_len;
    uint32_t last_len = 0;
    uint32_t data_offset = 0;

    if ((data_out == NULL) || (data_out->buffer == 0)) {
        return CRYPTO_BAD_PARAMETERS;
    }
    current_len = data_in->size + cipher_ctx->buf_offset;
    data_out->size = 0;
    if (current_len > CIPHER_BLOCK_LEN) {
        if (cipher_ctx->buf_offset != 0) {
            copy_len = CIPHER_BLOCK_LEN - cipher_ctx->buf_offset;
            if ((copy_len != 0) && (memcpy_s((void *)(cipher_ctx->buf + cipher_ctx->buf_offset),
                CIPHER_BLOCK_LEN - cipher_ctx->buf_offset,
                (void *)(uintptr_t)(data_in->buffer + data_offset), copy_len) != 0)) {
                goto CIPHER_UPDATE_Ex_Handle;
            }

            block_in.buffer = (uint64_t)(uintptr_t)cipher_ctx->buf;
            block_in.size = CIPHER_BLOCK_LEN;
            block_out.buffer = data_out->buffer + data_out->size;
            if (cipher_block_crypto(cipher_ctx, &block_in, &block_out) != CRYPTO_SUCCESS) {
                goto CIPHER_UPDATE_Ex_Handle;
            }
            data_out->size = CIPHER_BLOCK_LEN;
            cipher_ctx->buf_offset = 0;
            current_len = current_len - CIPHER_BLOCK_LEN;
            data_offset = copy_len;
        }
        if (cipher_update_cal(&current_len, &last_len, &data_offset, data_out, data_in, cipher_ctx) !=
            CRYPTO_SUCCESS) {
            goto CIPHER_UPDATE_Ex_Handle;
        }
    } else {
        last_len = data_in->size;
    }

    if ((last_len != 0) && (memcpy_s((void *)(cipher_ctx->buf + cipher_ctx->buf_offset), CIPHER_BLOCK_LEN,
        (void *)(uintptr_t)(data_in->buffer + data_offset), last_len) != 0)) {
        goto CIPHER_UPDATE_Ex_Handle;
    }
    cipher_ctx->buf_offset += last_len;

    return CRYPTO_SUCCESS;

CIPHER_UPDATE_Ex_Handle:
    return CRYPTO_ERROR_SECURITY;
}

STATIC int cipher_update(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    cipher_ctx_t *cipher_ctx = (cipher_ctx_t*)ctx;

    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if (data_out->size < (data_in->size + cipher_ctx->buf_offset)) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    return cipher_update_a(ctx, data_in, data_out);
}

STATIC int cipher_dofinal_a(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    uint32_t ret;
    cipher_ctx_t *cipher_ctx = (cipher_ctx_t*)ctx;
    struct memref_t block_in, block_out;

    data_out->size = 0;
    if ((data_in != NULL) && (data_in->buffer != 0)) {
        ret = cipher_update_a(ctx, data_in, data_out);
        if (ret != CRYPTO_SUCCESS) {
            return ret;
        }
    }

    block_in.buffer = (uint64_t)(uintptr_t)(cipher_ctx->buf);
    block_in.size = cipher_ctx->buf_offset;
    block_out.buffer = data_out->buffer + data_out->size;
    block_out.size = block_in.size;

    switch (cipher_ctx->padding_mode) {
        case PKCS5_PADDING:
            if (cipher_ctx->direct == AES_ENC) {
                if (cipher_ctx->buf_offset > (CIPHER_BLOCK_LEN + CIPHER_UNIT_LEN)) {
                    return CRYPTO_BAD_PARAMETERS;
                }
                uint32_t tail_len = CIPHER_BLOCK_BLEN - (cipher_ctx->buf_offset & AES_MASK_BLEN);
                cipher_set_padding((uint8_t *)(uintptr_t)block_in.buffer, tail_len, block_in.size);
                block_in.size += tail_len;
                ret = cipher_block_crypto(cipher_ctx, &block_in, &block_out);
            } else {
                if (cipher_block_crypto(cipher_ctx, &block_in, &block_out) != CRYPTO_SUCCESS) {
                    return CRYPTO_BAD_PARAMETERS;
                }
                ret = cipher_remove_padding((uint8_t *)(uintptr_t)block_out.buffer, &block_out.size);
            }
            break;
        case NO_PADDING:
            if ((cipher_ctx->buf_offset & AES_MASK_BLEN) != 0) {
                return CRYPTO_BAD_PARAMETERS;
            } // fall-through
        default:
            ret = cipher_block_crypto(cipher_ctx, &block_in, &block_out);
            break;
    }

    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    data_out->size += block_out.size;
    return CRYPTO_SUCCESS;
}

STATIC int cipher_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    uint32_t cal_len;
    cipher_ctx_t *cipher_ctx = (cipher_ctx_t*)ctx;

    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if ((data_out == NULL) || (data_out->buffer == 0)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if ((data_in != NULL) && (data_in->buffer != 0)) {
        cal_len = data_in->size + cipher_ctx->buf_offset;
    } else {
        cal_len = cipher_ctx->buf_offset;
    }

    if (data_out->size < cal_len) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    return cipher_dofinal_a(ctx, data_in, data_out);
}

STATIC int cipher(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *c_key, const struct memref_t *iv,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    uint32_t ret;
    cipher_ctx_t cipher_ctx;
    struct memref_t block_in;
    struct memref_t block_out;

    ret = cipher_init_a(alg_type, &cipher_ctx, direction, c_key, iv);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    block_in.buffer = data_in->buffer;
    block_in.size = data_in->size;
    block_out.buffer = data_out->buffer;
    block_out.size = data_out->size;

    ret = cipher_dofinal_a(&cipher_ctx, &block_in, &block_out);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    data_out->size = block_out.size;
    return CRYPTO_SUCCESS;
}

STATIC int ae_init(uint32_t alg_type, void *ctx, uint32_t direction, const struct symmerit_key_t *c_key,
    const struct ae_init_data *ae_init_param)
{
    ae_ctx_t *ae_ctx = (ae_ctx_t*)ctx;

    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if (alg_type != CRYPTO_TYPE_AES_GCM) {
        return CRYPTO_NOT_SUPPORTED;
    }

    if (ae_init_param->tag_len > AE_TAG_LEN) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if ((direction != ENC_MODE) && (direction != DEC_MODE)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if (memcpy_s((void *)ae_ctx->c_key, AE_KEY_MAX_LEN,
        (void *)(uintptr_t)c_key->key_buffer, c_key->key_size) != 0) {
        return CRYPTO_ERROR_SECURITY;
    }

    if (memcpy_s((void *)ae_ctx->cipher_iv, AE_IV_LEN,
        (void *)(uintptr_t)ae_init_param->nonce, ae_init_param->nonce_len) != 0) {
        return CRYPTO_ERROR_SECURITY;
    }

    ae_ctx->cipher_iv[IV_LAST_WORD_BYTE0] = 0;
    ae_ctx->cipher_iv[IV_LAST_WORD_BYTE1] = 0;
    ae_ctx->cipher_iv[IV_LAST_WORD_BYTE2] = 0;
    ae_ctx->cipher_iv[IV_LAST_WORD_BYTE3] = 1;

    if (memcpy_s((void *)ae_ctx->auth_iv, AE_IV_LEN, (void *)ae_ctx->cipher_iv, AE_IV_LEN) != 0) {
        return CRYPTO_ERROR_SECURITY;
    }

    if (memset_s((void *)(ae_ctx->auth_iv + AE_IV_LEN + AE_IV_LEN), AE_IV_LEN, 0, AE_IV_LEN) != 0) {
        return CRYPTO_ERROR_SECURITY;
    }

    ae_ctx->direct = direction + 1;
    ae_ctx->key_size = (c_key->key_size - AE_IV_LEN) >> SHIFT3;
    ae_ctx->tag_size = ae_init_param->tag_len;
    ae_ctx->total_data_size = 0;
    ae_ctx->buf_offset = 0;
    ae_ctx->aad_size = 0;
    return CRYPTO_SUCCESS;
}

STATIC int ae_update_aad(void *ctx, const struct memref_t *aad_data)
{
    ae_ctx_t *ae_ctx = (ae_ctx_t*)ctx;
    SEC_AES_GCM_INFO_S ae_info = {0};
    uint8_t mac_temp[AE_IV_LEN] = {0};
    uint8_t result_temp[AE_IV_LEN + AE_IV_LEN] = {0};
    uint8_t aad_buf[AAD_MAX_LEN] = {0};
    sec_bd_t bd;
    uint32_t ret;

    if (ctx == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if (aad_data->size > AAD_MAX_LEN) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if (memcpy_s((void *)aad_buf, aad_data->size,
        (void *)(uintptr_t)aad_data->buffer, aad_data->size) != 0) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    ae_ctx->aad_size = aad_data->size;
    ae_info.aes_enc = ae_ctx->direct;
    ae_info.aes_key_len = ae_ctx->key_size;
    ae_info.data_addr = (uint64_t)(uintptr_t)aad_buf;
    ae_info.iv_addr = (uint64_t)(uintptr_t)ae_ctx->cipher_iv;
    ae_info.key_addr = (uint64_t)(uintptr_t)ae_ctx->c_key;
    ae_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
    ae_info.aad_len = aad_data->size;
    ae_info.mac_addr = (uint64_t)(uintptr_t)mac_temp;
    ae_info.result_addr = (uint64_t)(uintptr_t)result_temp;

    ret = sec_aes_gcm_init(&ae_info);
    if (ret != SEC_SUCCESS) {
        return CRYPTO_CIPHERTEXT_INVALID;
    }

    if (memcpy_s((void *)(ae_ctx->auth_iv + AE_IV_LEN + AE_IV_LEN), AE_IV_LEN,
                 (void *)mac_temp, AE_IV_LEN) != 0) {
        return CRYPTO_ERROR_SECURITY;
    }

    return CRYPTO_SUCCESS;
}

STATIC int ae_block_update(ae_ctx_t *ae_ctx, struct memref_t *block_in, struct memref_t *block_out)
{
    SEC_AES_GCM_INFO_S ae_info = {0};
    uint8_t mac_temp[AE_IV_LEN] = {0};
    sec_bd_t bd;
    uint32_t ret;
    uint32_t counter = 0;

    block_out->size = block_in->size;

    if (block_in->size == 0) {
        return CRYPTO_SUCCESS;
    }

    ae_info.aes_enc = ae_ctx->direct;
    ae_info.aes_key_len = ae_ctx->key_size;
    ae_info.data_addr = (uint64_t)(uintptr_t)block_in->buffer;
    ae_info.data_len = block_in->size;
    ae_info.iv_addr = (uint64_t)(uintptr_t)ae_ctx->cipher_iv;
    ae_info.auth_iv_addr = (uint64_t)(uintptr_t)ae_ctx->auth_iv + AE_IV_LEN + AE_IV_LEN;
    ae_info.key_addr = (uint64_t)(uintptr_t)ae_ctx->c_key;
    ae_info.result_addr = (uint64_t)(uintptr_t)block_in->buffer;
    ae_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
    ae_info.mac_addr = (uint64_t)(uintptr_t)mac_temp;

    ret = sec_aes_gcm_update(&ae_info);
    if (ret != SEC_SUCCESS) {
        return CRYPTO_CIPHERTEXT_INVALID;
    }

    byte2wordr(&counter, ae_ctx->cipher_iv + IV_LAST_WORD_BYTE0, 1);
    counter += block_in->size >> SHIFT4;
    word2byter(&counter, ae_ctx->cipher_iv + IV_LAST_WORD_BYTE0, 1);

    if (memcpy_s((void *)(ae_ctx->auth_iv + AE_IV_LEN + AE_IV_LEN), AE_IV_LEN,
                 (void *)mac_temp, AE_IV_LEN) != 0) {
        return CRYPTO_SHORT_BUFFER;
    }

    if (memcpy_s((void *)(uintptr_t)block_out->buffer, block_out->size,
        (void *)(uintptr_t)block_in->buffer, block_in->size) != 0) {
        return CRYPTO_ERROR_SECURITY;
    }

    return CRYPTO_SUCCESS;
}

STATIC int ae_update_cal(uint32_t *current_len, uint32_t *last_len, uint32_t *data_offset, struct memref_t *data_out,
    const struct memref_t *data_in, ae_ctx_t *ae_ctx)
{
    struct memref_t block_in, block_out;
    uint32_t copy_len;
    uint8_t *space = NULL;
    space = (uint8_t *)malloc_coherent(SEC_PAGE_SIZE);
    if (space == NULL) {
        return CRYPTO_BAD_PARAMETERS;
    }

    while (*current_len >= (SEC_PAGE_SIZE + AE_BLOCK_LEN)) {
        if (memcpy_s((void *)space, SEC_PAGE_SIZE,
            (void *)(uintptr_t)(data_in->buffer + *data_offset), SEC_PAGE_SIZE) != 0) {
            goto AE_UPDATE_Ex_Handle;
        }

        block_in.buffer = (uint64_t)(uintptr_t)space;
        block_in.size = SEC_PAGE_SIZE;
        block_out.buffer = data_out->buffer + data_out->size;
        if (ae_block_update(ae_ctx, &block_in, &block_out) != CRYPTO_SUCCESS) {
            goto AE_UPDATE_Ex_Handle;
        }

        *current_len -= SEC_PAGE_SIZE;
        *data_offset += SEC_PAGE_SIZE;
        data_out->size += SEC_PAGE_SIZE;
    }

    copy_len = *current_len & BLOCK_LEN_MASK;
    *last_len = *current_len - copy_len;

    if (*last_len == 0) {
        copy_len -= AE_BLOCK_LEN;
        *last_len = AE_BLOCK_LEN;
    }

    if ((copy_len != 0) && (memcpy_s((void *)space, SEC_PAGE_SIZE,
        (void *)(uintptr_t)(data_in->buffer + *data_offset), copy_len) != 0)) {
        goto AE_UPDATE_Ex_Handle;
    }

    block_in.buffer = (uint64_t)(uintptr_t)space;
    block_in.size = copy_len;
    block_out.buffer = data_out->buffer + data_out->size;
    if (ae_block_update(ae_ctx, &block_in, &block_out) != CRYPTO_SUCCESS) {
        goto AE_UPDATE_Ex_Handle;
    }
    data_out->size += copy_len;
    *data_offset += copy_len;

    free(space);
    space = NULL;
    return CRYPTO_SUCCESS;
AE_UPDATE_Ex_Handle:
    free(space);
    space = NULL;
    return CRYPTO_BAD_PARAMETERS;
}

STATIC int ae_update_a(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    ae_ctx_t *ae_ctx = (ae_ctx_t*)ctx;
    struct memref_t block_in, block_out;
    uint32_t data_offset, copy_len, current_len, last_len;

    ae_ctx->total_data_size += data_in->size;
    data_offset = 0;
    data_out->size = 0;
    current_len = ae_ctx->buf_offset + data_in->size;

    if (current_len > AE_BLOCK_LEN) {
        if (ae_ctx->buf_offset != 0) {
            copy_len = AE_BLOCK_LEN - ae_ctx->buf_offset;
            if ((copy_len != 0) && (memcpy_s((void *)(ae_ctx->buf + ae_ctx->buf_offset),
                sizeof(ae_ctx->buf) - ae_ctx->buf_offset,
                (void *)(uintptr_t)(data_in->buffer + data_offset), copy_len) != 0)) {
                goto AE_UPDATE_Ex_Handle;
            }

            block_in.buffer = (uint64_t)(uintptr_t)ae_ctx->buf;
            block_in.size = AE_BLOCK_LEN;
            block_out.buffer = data_out->buffer + data_out->size;

            if (ae_block_update(ae_ctx, &block_in, &block_out) != CRYPTO_SUCCESS)
                goto AE_UPDATE_Ex_Handle;

            data_out->size = AE_BLOCK_LEN;
            ae_ctx->buf_offset = 0;
            current_len = current_len - AE_BLOCK_LEN;
            data_offset = copy_len;
        }
        if (ae_update_cal(&current_len, &last_len, &data_offset, data_out, data_in, ae_ctx) !=
            CRYPTO_SUCCESS) {
            goto AE_UPDATE_Ex_Handle;
        }
    } else {
        last_len = data_in->size;
    }

    if ((last_len != 0) && (memcpy_s((void *)(ae_ctx->buf + ae_ctx->buf_offset), sizeof(ae_ctx->buf) -
        ae_ctx->buf_offset, (const void *)(uintptr_t)(data_in->buffer + data_offset), last_len) != 0)) {
        goto AE_UPDATE_Ex_Handle;
    }

    ae_ctx->buf_offset += last_len;
    return CRYPTO_SUCCESS;

AE_UPDATE_Ex_Handle:
    return CRYPTO_BAD_PARAMETERS;
}

STATIC int ae_update(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    ae_ctx_t *ae_ctx = (ae_ctx_t*)ctx;

    if ((ctx == NULL) || (data_out == NULL) || (data_out->buffer == 0)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if (data_out->size < (data_in->size + ae_ctx->buf_offset)) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    return ae_update_a(ctx, data_in, data_out);
}

STATIC int ae_enc_final_para_check(void *ctx, const struct memref_t *data_in, struct memref_t *data_out,
    struct memref_t *tag_out)
{
    uint32_t cal_len;
    ae_ctx_t *ae_ctx = (ae_ctx_t*)ctx;

    if ((data_out == NULL) || (tag_out == NULL)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if ((ctx == NULL) || (data_out->buffer == 0) || (tag_out->buffer == 0)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if ((data_in != NULL) && (data_in->buffer != 0)) {
        cal_len = data_in->size + ae_ctx->buf_offset;
    } else {
        cal_len = ae_ctx->buf_offset;
    }

    if ((data_out->size < cal_len) || (tag_out->size < ae_ctx->tag_size)) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    return CRYPTO_SUCCESS;
}

STATIC int ae_enc_final(void *ctx, const struct memref_t *data_in, struct memref_t *data_out,
    struct memref_t *tag_out)
{
    uint32_t ret;
    SEC_AES_GCM_INFO_S ae_info = {0};
    ae_ctx_t *ae_ctx = (ae_ctx_t*)ctx;
    sec_bd_t bd;

    ret = ae_enc_final_para_check(ctx, data_in, data_out, tag_out);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    data_out->size = 0;
    if ((data_in != NULL) && (data_in->buffer != 0)) {
        ret = ae_update_a(ctx, data_in, data_out);
        if (ret != CRYPTO_SUCCESS) {
            return ret;
        }
    }

    ae_info.aes_enc = ae_ctx->direct;
    ae_info.aes_key_len = ae_ctx->key_size;
    ae_info.data_addr = (uint64_t)(uintptr_t)ae_ctx->buf;
    ae_info.data_len = ae_ctx->buf_offset;
    ae_info.iv_addr = (uint64_t)(uintptr_t)ae_ctx->cipher_iv;
    ae_info.auth_iv_addr = (uint64_t)(uintptr_t)ae_ctx->auth_iv;
    ae_info.key_addr = (uint64_t)(uintptr_t)ae_ctx->c_key;
    ae_info.result_addr = (uint64_t)(uintptr_t)ae_ctx->buf;
    ae_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
    ae_info.mac_addr = (uint64_t)(uintptr_t)ae_ctx->buf2;
    ae_info.tag_len = ae_ctx->tag_size;
    ae_info.long_data_len_h = ae_ctx->total_data_size >> SHIFT8;
    ae_info.long_data_len_l = (ae_ctx->total_data_size << SHIFT24) | (ae_ctx->aad_size);

    ret = sec_aes_gcm_final(&ae_info);
    if (ret != SEC_SUCCESS) {
        return CRYPTO_CIPHERTEXT_INVALID;
    }

    if (memcpy_s((void *)(uintptr_t)tag_out->buffer, ae_ctx->tag_size,
                 (void *)ae_ctx->buf2, ae_ctx->tag_size) != 0) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    if (memcpy_s((void *)(uintptr_t)(data_out->buffer + data_out->size), ae_ctx->buf_offset,
                 (void *)ae_ctx->buf, ae_ctx->buf_offset) != 0) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    data_out->size += ae_ctx->buf_offset;
    tag_out->size = ae_ctx->tag_size;
    return CRYPTO_SUCCESS;
}

STATIC int ae_dec_final_para_check(void *ctx, const struct memref_t *data_in, const struct memref_t *tag_in,
    struct memref_t *data_out)
{
    uint32_t cal_len;
    ae_ctx_t *ae_ctx = (ae_ctx_t*)ctx;

    if ((ctx == NULL) || (data_out == NULL) || (data_out->buffer == 0)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if (tag_in->size != ae_ctx->tag_size) {
        return CRYPTO_MAC_INVALID;
    }

    if ((data_in != NULL) && (data_in->buffer != 0)) {
        cal_len = data_in->size + ae_ctx->buf_offset;
    } else {
        cal_len = ae_ctx->buf_offset;
    }

    if (data_out->size < cal_len) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    return CRYPTO_SUCCESS;
}

STATIC int ae_dec_final(void *ctx, const struct memref_t *data_in, const struct memref_t *tag_in,
    struct memref_t *data_out)
{
    uint32_t ret;
    SEC_AES_GCM_INFO_S ae_info = {0};
    ae_ctx_t *ae_ctx = (ae_ctx_t*)ctx;
    sec_bd_t bd;

    ret = ae_dec_final_para_check(ctx, data_in, tag_in, data_out);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    data_out->size = 0;
    if ((data_in != NULL) && (data_in->buffer != 0)) {
        ret = ae_update_a(ctx, data_in, data_out);
        if (ret != CRYPTO_SUCCESS) {
            return ret;
        }
    }

    if (memcpy_s((void *)ae_ctx->buf2, sizeof(ae_ctx->buf2),
                 (void *)(uintptr_t)tag_in->buffer, ae_ctx->tag_size) != 0) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    ae_info.aes_enc = ae_ctx->direct;
    ae_info.aes_key_len = ae_ctx->key_size;
    ae_info.data_addr = (uint64_t)(uintptr_t)ae_ctx->buf;
    ae_info.data_len = ae_ctx->buf_offset;
    ae_info.iv_addr = (uint64_t)(uintptr_t)ae_ctx->cipher_iv;
    ae_info.auth_iv_addr = (uint64_t)(uintptr_t)ae_ctx->auth_iv;
    ae_info.key_addr = (uint64_t)(uintptr_t)ae_ctx->c_key;
    ae_info.result_addr = (uint64_t)(uintptr_t)ae_ctx->buf;
    ae_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
    ae_info.mac_addr = (uint64_t)(uintptr_t)ae_ctx->buf2;
    ae_info.tag_len = ae_ctx->tag_size;
    ae_info.long_data_len_h = ae_ctx->total_data_size >> SHIFT8;
    ae_info.long_data_len_l = (ae_ctx->total_data_size << SHIFT24) | (ae_ctx->aad_size);

    ret = sec_aes_gcm_final(&ae_info);
    if (ret != SEC_SUCCESS) {
        return CRYPTO_CIPHERTEXT_INVALID;
    }

    if (memcpy_s((void *)(uintptr_t)(data_out->buffer + data_out->size), ae_ctx->buf_offset,
                 (void *)ae_ctx->buf, ae_ctx->buf_offset) != 0) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    data_out->size += ae_ctx->buf_offset;
    return CRYPTO_SUCCESS;
}

STATIC int ctx_copy(uint32_t alg_type, const void *src_ctx, uint32_t src_size, void *dest_ctx, uint32_t dest_size)
{
    uint32_t size;
    uint32_t i;

    if ((src_ctx == NULL) || (dest_ctx == NULL)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    for (i = 0; i < (sizeof(g_ctx_size_map) / sizeof(ctx_size_map_s)); i++) {
        if (alg_type == g_ctx_size_map[i].alg_type) {
            size = g_ctx_size_map[i].ctx_size;
            if ((size > src_size) || (size > dest_size)) {
                return CRYPTO_SHORT_BUFFER;
            }
            if (memcpy_s(dest_ctx, dest_size, src_ctx, size) != 0) {
                return CRYPTO_ERROR_OUT_OF_MEMORY;
            }
            return CRYPTO_SUCCESS;
        }
    }
    return CRYPTO_NOT_SUPPORTED;
}

STATIC int generate_random(void *buffer, size_t size)
{
    return (int)trng_distribute((uint8_t *)buffer, size);
}

STATIC int pbkdf2(const struct memref_t *c_password, const struct memref_t *salt, uint32_t iterations,
    uint32_t digest_type, struct memref_t *data_out)
{
    uint32_t ret;
    uint32_t alg, outlen;
    SEC_PBKDF2_INFO_S pbkdf2_info = {0};
    derive_key_ctx_t derive_ctx = { {0}, {0}, 0, 0 };
    sec_bd_t bd;

    if ((data_out == NULL) || (data_out->buffer == 0)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    if ((data_out->size > DERIVE_KEY_MAX_OUT) || (salt->size > DERIVE_SALT_MAX_IN)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    derive_ctx.key_len = data_out->size;
    derive_ctx.salt_len = salt->size;

    ret = memcpy_s((void *)derive_ctx.derive_salt, DERIVE_SALT_MAX_IN,
                   (void *)(uintptr_t)salt->buffer, salt->size);
    if (ret != EOK) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    ret = hmac_option_select(digest_type, &alg, &outlen);
    if (ret != CRYPTO_SUCCESS) {
        return CRYPTO_NOT_SUPPORTED;
    }

    pbkdf2_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
    pbkdf2_info.key_addr = (uint64_t)c_password->buffer;
    pbkdf2_info.cnt = iterations;
    pbkdf2_info.key_len = c_password->size;
    pbkdf2_info.hmac_type = alg;
    pbkdf2_info.seed_addr = (uint64_t)derive_ctx.derive_salt;
    pbkdf2_info.seed_len = derive_ctx.salt_len;
    pbkdf2_info.mac_len = derive_ctx.key_len;
    pbkdf2_info.result_addr = (uint64_t)derive_ctx.derive_key;

    ret = sec_pbkdf2(&pbkdf2_info);
    if (ret != SEC_SUCCESS) {
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = memcpy_s((void *)(uintptr_t)data_out->buffer, data_out->size,
                   (void *)derive_ctx.derive_key, derive_ctx.key_len);
    if (ret != EOK) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    return CRYPTO_SUCCESS;
}

STATIC int derive_root_key(uint32_t derive_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)derive_type;
    uint32_t ret;
    SEC_PBKDF2_INFO_S pbkdf2_info = {0};
    derive_key_ctx_t derive_ctx = { {0}, {0}, 0, 0 };
    sec_bd_t bd;

    if ((data_out == NULL) || (data_out->buffer == 0) || (data_out->size > DERIVE_KEY_MAX_OUT) ||
        (data_in->size > DERIVE_SALT_MAX_IN) || (data_out->size == 0) || (data_in->size == 0)) {
        return CRYPTO_BAD_PARAMETERS;
    }

    derive_ctx.key_len = data_out->size;
    derive_ctx.salt_len = data_in->size;

    ret = memcpy_s((void *)derive_ctx.derive_salt, DERIVE_SALT_MAX_IN,
                   (void *)(uintptr_t)data_in->buffer, data_in->size);
    if (ret != EOK) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    pbkdf2_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
    pbkdf2_info.key_addr = 0;
    pbkdf2_info.cnt = DERIVE_KEY_DEFAULT_ITR;
    pbkdf2_info.key_len = ROOT_KEY_SIZE;
    pbkdf2_info.hmac_type = HMAC_SHA256;
    pbkdf2_info.seed_addr = (uint64_t)(uintptr_t)derive_ctx.derive_salt;
    pbkdf2_info.seed_len = derive_ctx.salt_len;
    pbkdf2_info.mac_len = derive_ctx.key_len;
    pbkdf2_info.key_type = HUK;
    pbkdf2_info.result_addr = (uint64_t)(uintptr_t)derive_ctx.derive_key;

    ret = sec_pbkdf2(&pbkdf2_info);
    if (ret != SEC_SUCCESS) {
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = memcpy_s((void *)(uintptr_t)data_out->buffer, data_out->size,
                   (void *)derive_ctx.derive_key, derive_ctx.key_len);
    if (ret != EOK) {
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    return CRYPTO_SUCCESS;
}
#ifndef CRYPTO_MGR_SERVER_ENABLE
const static struct crypto_ops_t g_crypto_ops = {
    NULL,
    NULL,
    get_ctx_size,
    ctx_copy,
    get_driver_ability,
    hash_init,
    hash_update,
    hash_dofinal,
    hash_simple,
    hmac_init,
    hmac_update,
    hmac_dofinal,
    hmac,
    cipher_init,
    cipher_update,
    cipher_dofinal,
    cipher,
    ae_init,
    ae_update_aad,
    ae_update,
    ae_enc_final,
    ae_dec_final,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    generate_random,
    0,
    derive_root_key,
    pbkdf2
};
#else
const static struct crypto_ops_t g_crypto_ops = { 0 };
#endif

STATIC int32_t sec_adapt_init(void)
{
    return register_crypto_ops(SEC_CRYPTO_FLAG, &g_crypto_ops);
}

DECLARE_TC_DRV(
    crypto_sec_adapt,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    sec_adapt_init,
    NULL,
    NULL,
    NULL,
    NULL
);
