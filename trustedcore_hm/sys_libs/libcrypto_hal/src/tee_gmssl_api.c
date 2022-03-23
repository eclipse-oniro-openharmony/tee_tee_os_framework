/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: process keymaster crypto info
 * Create: 2018.7.16
 */

#include "tee_gmssl_api.h"
#include <dlfcn.h>
/* SM_SUPPORT */
#include <sm3.h>
#include <openssl/obj_mac.h>
#ifndef BORINGSSL_ENABLE
#include <openssl/ossl_typ.h>
#endif
#include <securec.h>
#include <tee_log.h>
#include <tee_crypto_api.h>
#include <tee_crypto_err.h>
#include <tee_property_inner.h>
#include "crypto_inner_defines.h"

/* GM_NID_SM3 is diff between gmssl and openssl, so define a new micro */
#define GM_NID_SM3       1126
#define KEY_SIZE         32
#define KEY_SIZE_2       64
#define DIGEST_ALLOC_CTX 1
#define SM2_MAX_KEY_SIZE 68
#define GM_ERR           0
#define SM2_SIG_LEN      64

void *g_libgm = NULL;
#ifdef __aarch64__
static const char *g_libgm_path = "/libgm_shared.so";
#else
static const char *g_libgm_path = "/libgm_shared_a32.so";
#endif

static int32_t get_soft_crypto_error(int32_t alg_id, int32_t tee_error)
{
    int32_t (*get_gmssl_error_ptr)(int32_t alg_id, int32_t tee_error) = NULL;

    get_gmssl_error_ptr = dlsym(g_libgm, "get_gmssl_error");
    if (get_gmssl_error_ptr == NULL) {
        tloge("gmssl error not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    return get_gmssl_error_ptr(alg_id, tee_error);
}

static int32_t tee_sm2_sign_old_version(const uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len, EC_KEY *ec_key)
{
    if (*signature_len < SM2_SIG_LEN) {
        tloge("output buffer is not large enough! signature length= %u\n", *signature_len);
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t (*sm2_sign_ptr)(const uint8_t *dgst, uint32_t dgstlen,
        uint8_t *sig, uint32_t *siglen, EC_KEY *eckey) = NULL;

    sm2_sign_ptr = dlsym(g_libgm, "libgm_sm2_sign");
    if (sm2_sign_ptr == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t result = sm2_sign_ptr(digest, digest_len, signature, signature_len, ec_key);
    if (result != CRYPTO_SUCCESS) {
        tloge("sm2 sign failed\n");
        return result;
    }
    return CRYPTO_SUCCESS;
}

static int32_t tee_sm2_sign_new_version(const uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len, EC_KEY *ec_key)
{
    int32_t type = GM_NID_SM3;
    if (*signature_len < SM2_SIGN_MAX) {
        tloge("output buffer is not large enough! signature length = %u\n", *signature_len);
        return CRYPTO_SHORT_BUFFER;
    }

    int32_t (*sm2_sign_ptr)(int32_t type, const uint8_t *dgst, int32_t dgstlen,
        uint8_t *sig, uint32_t *siglen, EC_KEY *eckey) = NULL;

    sm2_sign_ptr = dlsym(g_libgm, "SM2_sign");
    if (sm2_sign_ptr == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t result = sm2_sign_ptr(type, digest, digest_len, signature, signature_len, ec_key);
    if (result == GM_ERR) {
        tloge("sm2 sign failed\n");
        return get_soft_crypto_error(SM2_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    return CRYPTO_SUCCESS;
}

static int32_t tee_sm2_sign(const uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len, EC_KEY *ec_key)
{
    uint32_t api_leval = tee_get_ta_api_level();
    if (api_leval > API_LEVEL1_0)
        return tee_sm2_sign_old_version(digest, digest_len, signature, signature_len, ec_key);
    else
        return tee_sm2_sign_new_version(digest, digest_len, signature, signature_len, ec_key);
}

static int32_t tee_sm2_verify_old_version(const uint8_t *digest, uint32_t digest_len,
    const uint8_t *signature, uint32_t signature_len, EC_KEY *ec_key)
{
    if (signature_len != SM2_SIG_LEN) {
        tloge("output buffer is too large , signature length = %u!\n", signature_len);
        return TEE_ERROR_SHORT_BUFFER;
    }
    int32_t(*sm2_verify_ptr)(const uint8_t *dgst, uint32_t dgstlen,
        const uint8_t *sig, uint32_t siglen, EC_KEY *ec_key) = NULL;

    sm2_verify_ptr = dlsym(g_libgm, "libgm_sm2_verify");
    if (sm2_verify_ptr == NULL) {
        tloge("gmssl not support");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = sm2_verify_ptr(digest, digest_len, signature, signature_len, ec_key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("sm2 verify failed\n");
        return get_soft_crypto_error(SM2_LIB_ERR_ID, TEE_ERROR_SIGNATURE_INVALID);
    }
    return CRYPTO_SUCCESS;
}

static int32_t tee_sm2_verify_new_version(const uint8_t *digest, uint32_t digest_len,
    const uint8_t *signature, uint32_t signature_len, EC_KEY *ec_key)
{
    int32_t type = GM_NID_SM3;
    if (signature_len > SM2_SIGN_MAX) {
        tloge("output buffer is too large , signature length = %u!\n", signature_len);
        return TEE_ERROR_SHORT_BUFFER;
    }
    int32_t (*sm2_verify_ptr)(int32_t type, const uint8_t *dgst, int32_t dgstlen,
        const uint8_t *sig, int32_t siglen, EC_KEY *ec_key) = NULL;

    sm2_verify_ptr = dlsym(g_libgm, "SM2_verify");
    if (sm2_verify_ptr == NULL) {
        tloge("gmssl not support");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t result = sm2_verify_ptr(type, digest, digest_len, signature, signature_len, ec_key);
    if (result <= GM_ERR) {
        tloge("sm2 verify failed\n");
        return get_soft_crypto_error(SM2_LIB_ERR_ID, TEE_ERROR_SIGNATURE_INVALID);
    }
    return CRYPTO_SUCCESS;
}

static int32_t tee_sm2_verify(const uint8_t *digest, uint32_t digest_len,
    const uint8_t *signature, uint32_t signature_len, EC_KEY *ec_key)
{
    uint32_t api_leval = tee_get_ta_api_level();
    if (api_leval > API_LEVEL1_0)
        return tee_sm2_verify_old_version(digest, digest_len, signature, signature_len, ec_key);
    else
        return tee_sm2_verify_new_version(digest, digest_len, signature, signature_len, ec_key);
}

static EC_KEY *creat_sm2_ec_key(const void *sm2_key, uint32_t mode)
{
    EC_KEY *(*get_sm2_key_ptr)(const void *sm2_key, uint32_t mode) = NULL;

    uint32_t api_leval = tee_get_ta_api_level();
    if (api_leval > API_LEVEL1_0)
        get_sm2_key_ptr = dlsym(g_libgm, "get_sm2_key_2");
    else
        get_sm2_key_ptr = dlsym(g_libgm, "get_sm2_key");

    if (get_sm2_key_ptr == NULL) {
        tloge("gmssl not support\n");
        return NULL;
    }

    return get_sm2_key_ptr(sm2_key, mode);
}

static int32_t check_and_open_gm(bool check)
{
    if (check) {
        tloge("input is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed\n");
            return CRYPTO_NOT_SUPPORTED;
        }
    }
    return CRYPTO_SUCCESS;
}

int32_t sm2_sign_verify(const void *sm2_key, uint32_t mode, const struct memref_t *digest,
    struct memref_t *signature)
{
    bool check = (sm2_key == NULL || digest == NULL || signature == NULL);

    int32_t ret = check_and_open_gm(check);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    void (*free_sm2_ec_key)(EC_KEY *key) = NULL;
    free_sm2_ec_key = dlsym(g_libgm, "EC_KEY_free");
    if (free_sm2_ec_key == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    EC_KEY *ec_key = creat_sm2_ec_key(sm2_key, mode);
    if (ec_key == NULL) {
        tloge("creat sm2 ec key failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (mode == SIGN_MODE) {
        ret = tee_sm2_sign((uint8_t *)(uintptr_t)(digest->buffer), digest->size,
            (uint8_t *)(uintptr_t)(signature->buffer), &(signature->size), ec_key);
    } else if (mode == VERIFY_MODE) {
        ret = tee_sm2_verify((uint8_t *)(uintptr_t)(digest->buffer), digest->size,
            (const uint8_t *)(uintptr_t)(signature->buffer), signature->size, ec_key);
    } else {
        tloge("invalid mode %u\n", mode);
        ret = CRYPTO_BAD_PARAMETERS;
    }

    free_sm2_ec_key(ec_key);
    return ret;
}

int32_t sm2_encrypt_decypt(const void *sm2_key, uint32_t mode,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    int32_t (*libgm_sm2_encrypt_decypt_ptr)(const void *sm2_key, uint32_t mode,
        const struct memref_t *data_in, struct memref_t *data_out) = NULL;

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed!");
            return CRYPTO_NOT_SUPPORTED;
        }
    }

    uint32_t api_leval = tee_get_ta_api_level();
    if (api_leval > API_LEVEL1_0)
        libgm_sm2_encrypt_decypt_ptr = dlsym(g_libgm, "libgm_sm2_encrypt_decypt_2");
    else
        libgm_sm2_encrypt_decypt_ptr = dlsym(g_libgm, "libgm_sm2_encrypt_decypt");

    if (libgm_sm2_encrypt_decypt_ptr == NULL) {
        tloge("gmssl not support!\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    return libgm_sm2_encrypt_decypt_ptr(sm2_key, mode, data_in, data_out);
}

int32_t sm4_cipher_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key, const struct memref_t *iv)
{
    bool check = (ctx == NULL || key == NULL || key->key_buffer == 0 || key->key_size == 0);

    int32_t ret = check_and_open_gm(check);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    void *(*libgm_sm4_cipher_init_ptr)(uint32_t alg_type, uint32_t direction,
        const struct symmerit_key_t *key, const struct memref_t *iv) = NULL;

    libgm_sm4_cipher_init_ptr = dlsym(g_libgm, "libgm_sm4_cipher_init");
    if (libgm_sm4_cipher_init_ptr == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    void *sm4_ctx = libgm_sm4_cipher_init_ptr(ctx->alg_type, ctx->direction, key, iv);
    if (sm4_ctx == NULL) {
        tloge("sm4 init failed");
        return get_soft_crypto_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    ctx->ctx_buffer = (uint64_t)(uintptr_t)sm4_ctx;
    ctx->free_context = free_sm4_context;
    return CRYPTO_SUCCESS;
}

int32_t sm4_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    bool check = (ctx == NULL || data_in == NULL || data_out == NULL ||
        data_in->size == 0 || data_out->size == 0);
    if (check) {
        tloge("input is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t (*libgm_sm4_update_ptr)(struct ctx_handle_t *ctx, const struct memref_t *data_in,
        struct memref_t *data_out) = NULL;

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed\n");
            return CRYPTO_NOT_SUPPORTED;
        }
    }
    libgm_sm4_update_ptr = dlsym(g_libgm, "libgm_sm4_update");
    if (libgm_sm4_update_ptr == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    return libgm_sm4_update_ptr(ctx, data_in, data_out);
}

int32_t sm4_cipher_do_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    bool check = (ctx == NULL || data_in == NULL || data_out == NULL || data_out->buffer == 0 ||
        data_out->size == 0);
    if (check) {
        tloge("input is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t (*libgm_sm4_do_final_ptr)(struct ctx_handle_t *ctx, const struct memref_t *data_in,
        struct memref_t *data_out) = NULL;

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed\n");
            return CRYPTO_NOT_SUPPORTED;
        }
    }
    libgm_sm4_do_final_ptr = dlsym(g_libgm, "libgm_sm4_do_final");
    if (libgm_sm4_do_final_ptr == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    return libgm_sm4_do_final_ptr(ctx, data_in, data_out);
}

int32_t sm2_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    int32_t (*libgm_sm2_generate_keypair_ptr)(uint32_t key_size, uint32_t curve,
        struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key) = NULL;

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed!");
            return CRYPTO_NOT_SUPPORTED;
        }
    }
    uint32_t api_leval = tee_get_ta_api_level();
    if (api_leval > API_LEVEL1_0)
        libgm_sm2_generate_keypair_ptr = dlsym(g_libgm, "libgm_sm2_generate_keypair_2");
    else
        libgm_sm2_generate_keypair_ptr = dlsym(g_libgm, "libgm_sm2_generate_keypair");

    if (libgm_sm2_generate_keypair_ptr == NULL) {
        tloge("gmssl not support!\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    return libgm_sm2_generate_keypair_ptr(key_size, curve, public_key, private_key);
}

int32_t sm3_mac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key)
{
    bool check = (ctx == NULL || key == NULL || key->key_buffer == 0 || key->key_size == 0);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed!\n");
            return CRYPTO_NOT_SUPPORTED;
        }
    }
    void (*sm3_hmac_init_ptr)(sm3_hmac_ctx_t *ctx, const unsigned char *key, size_t key_len) = NULL;
    sm3_hmac_init_ptr = dlsym(g_libgm, "sm3_hmac_init");
    if (sm3_hmac_init_ptr == NULL) {
        tloge("gmssl not support!\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    sm3_hmac_ctx_t *hmac_ctx = TEE_Malloc(sizeof(*hmac_ctx), 0);
    if (hmac_ctx == NULL) {
        tloge("malloc failed!\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    sm3_hmac_init_ptr(hmac_ctx, (const unsigned char *)(uintptr_t)(key->key_buffer), key->key_size);
    ctx->ctx_buffer = (uint64_t)(uintptr_t)hmac_ctx;
    ctx->ctx_size = sizeof(*hmac_ctx);

    return CRYPTO_SUCCESS;
}

int32_t sm3_mac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    bool check = (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL ||
        data_in->buffer == 0 || data_in->size == 0);
    if (check) {
        tloge("bad params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed!\n");
            return CRYPTO_NOT_SUPPORTED;
        }
    }

    void (*sm3_hmac_update_ptr)(sm3_hmac_ctx_t *ctx, const unsigned char *data, size_t data_len) = NULL;
    sm3_hmac_update_ptr = dlsym(g_libgm, "sm3_hmac_update");
    if (sm3_hmac_update_ptr == NULL) {
        tloge("gmssl not support!\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    sm3_hmac_update_ptr((sm3_hmac_ctx_t *)(uintptr_t)(ctx->ctx_buffer),
        (const unsigned char *)(uintptr_t)(data_in->buffer), data_in->size);
    return CRYPTO_SUCCESS;
}

static int32_t sm3_check(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    if (ctx == NULL || ctx->ctx_buffer == 0)
        return CRYPTO_BAD_PARAMETERS;

    bool check = (data_out == NULL || data_out->buffer == 0 || data_out->size < SM3_DIGEST_LENGTH);
    if (check) {
        tloge("context is NULL");
        TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
        ctx->ctx_buffer = 0;
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

int32_t sm3_mac_computefinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    if (sm3_check(ctx, data_out) != CRYPTO_SUCCESS)
        return CRYPTO_BAD_PARAMETERS;

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed!");
            TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
            ctx->ctx_buffer = 0;
            return CRYPTO_NOT_SUPPORTED;
        }
    }

    void (*sm3_hmac_final_ptr)(sm3_hmac_ctx_t *ctx, unsigned char mac[SM3_HMAC_SIZE]) = NULL;
    sm3_hmac_final_ptr = dlsym(g_libgm, "sm3_hmac_final");
    if (sm3_hmac_final_ptr == NULL) {
        tloge("gmssl not support!\n");
        TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
        ctx->ctx_buffer = 0;
        return CRYPTO_NOT_SUPPORTED;
    }

    sm3_hmac_final_ptr((sm3_hmac_ctx_t *)(uintptr_t)(ctx->ctx_buffer),
        (unsigned char *)(uintptr_t)data_out->buffer);
    data_out->size = SM3_DIGEST_LENGTH;

    TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
    ctx->ctx_buffer = 0;
    return CRYPTO_SUCCESS;
}

int32_t sm3_digest_init(struct ctx_handle_t *ctx)
{
    if (ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed!");
            return CRYPTO_NOT_SUPPORTED;
        }
    }

    void (*sm3_init_ptr)(sm3_ctx_t *ctx) = NULL;
    sm3_init_ptr = dlsym(g_libgm, "sm3_init");
    if (sm3_init_ptr == NULL) {
        tloge("gmssl not support!\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    sm3_ctx_t *sm3_ctx = TEE_Malloc(sizeof(*sm3_ctx), 0);
    if (sm3_ctx == NULL) {
        tloge("malloc context failed!\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    sm3_init_ptr(sm3_ctx);

    ctx->ctx_buffer = (uint64_t)(uintptr_t)sm3_ctx;
    ctx->ctx_size = sizeof(*sm3_ctx);

    return CRYPTO_SUCCESS;
}

int32_t sm3_digest_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    bool check = (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL ||
        data_in->buffer == 0 || data_in->size == 0);
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed!");
            return CRYPTO_NOT_SUPPORTED;
        }
    }
    void (*sm3_update_ptr)(sm3_ctx_t *ctx, const unsigned char *data, size_t data_len) = NULL;

    sm3_update_ptr = dlsym(g_libgm, "sm3_update");
    if (sm3_update_ptr == NULL) {
        tloge("gmssl not supported!");
        return CRYPTO_NOT_SUPPORTED;
    }

    sm3_update_ptr((sm3_ctx_t *)(uintptr_t)(ctx->ctx_buffer), (const unsigned char *)(uintptr_t)data_in->buffer,
        data_in->size);

    return CRYPTO_SUCCESS;
}

int32_t sm3_digest_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    if (sm3_check(ctx, data_out) != CRYPTO_SUCCESS)
        return CRYPTO_BAD_PARAMETERS;

    void (*sm3_final_ptr)(sm3_ctx_t *ctx, unsigned char digest[SM3_DIGEST_LENGTH]) = NULL;

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed!");
            TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
            ctx->ctx_buffer = 0;
            return CRYPTO_NOT_SUPPORTED;
        }
    }

    sm3_final_ptr = dlsym(g_libgm, "sm3_final");
    if (sm3_final_ptr == NULL) {
        tloge("gmssl not supported!");
        TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
        ctx->ctx_buffer = 0;
        return CRYPTO_NOT_SUPPORTED;
    }

    sm3_final_ptr((sm3_ctx_t *)(uintptr_t)ctx->ctx_buffer, (unsigned char *)(uintptr_t)(data_out->buffer));
    data_out->size = SM3_DIGEST_LENGTH;

    TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
    ctx->ctx_buffer = 0;
    return CRYPTO_SUCCESS;
}

static int32_t copy_sm_buf_info(uint64_t *dst_buf, const uint64_t src_buf, uint32_t src_size)
{
    TEE_Free((void *)(uintptr_t)*dst_buf);
    *dst_buf = 0;
    bool check = ((src_buf == 0) || (src_size == 0));
    if (check)
        return CRYPTO_SUCCESS;

    *dst_buf = (uint64_t)(uintptr_t)TEE_Malloc(src_size, TEE_MALLOC_FILL_ZERO);
    if (*dst_buf == 0) {
        tloge("dst_buf malloc failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int ret = memcpy_s((void *)(uintptr_t)*dst_buf, src_size, (void *)(uintptr_t)src_buf, src_size);
    if (ret != 0)
        return CRYPTO_ERROR_SECURITY;

    return CRYPTO_SUCCESS;
}

static int32_t copy_sm4_operation(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    int32_t (*copy_sm4_operation_ptr)(struct ctx_handle_t *dest,
        const struct ctx_handle_t *src) = NULL;

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed!\n");
            return CRYPTO_NOT_SUPPORTED;
        }
    }
    copy_sm4_operation_ptr = dlsym(g_libgm, "libgm_copy_sm4_operation");
    if (copy_sm4_operation_ptr == NULL) {
        tloge("gmssl not support!\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    return copy_sm4_operation_ptr(dest, src);
}

int32_t soft_copy_gmssl_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    bool check = (dest == NULL || src == NULL);
    if (check) {
        tloge("Invalid params!\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    switch (src->alg_type) {
    case TEE_ALG_SM3:
        return copy_sm_buf_info(&(dest->ctx_buffer), src->ctx_buffer, sizeof(sm3_ctx_t));
    case TEE_ALG_HMAC_SM3:
        return copy_sm_buf_info(&(dest->ctx_buffer), src->ctx_buffer, sizeof(sm3_hmac_ctx_t));
    case TEE_ALG_SM4_ECB_NOPAD:
    case TEE_ALG_SM4_CBC_NOPAD:
    case TEE_ALG_SM4_CBC_PKCS7:
    case TEE_ALG_SM4_CTR:
    case TEE_ALG_SM4_CFB128:
    case TEE_ALG_SM4_GCM:
        return copy_sm4_operation(dest, src);
    default:
        return CRYPTO_SUCCESS;
    }
}

void free_sm4_context(uint64_t *ctx)
{
    bool check = (ctx == NULL || *ctx == 0);
    if (check) {
        tloge("Invalid params!\n");
        return;
    }

    void (*evp_cipher_ctx_free_ptr)(uint64_t *) = NULL;

    if (g_libgm == NULL) {
        g_libgm = dlopen(g_libgm_path, RTLD_NOW | RTLD_LOCAL);
        if (g_libgm == NULL) {
            tloge("load libgm_shared failed!\n");
            return;
        }
    }
    evp_cipher_ctx_free_ptr = dlsym(g_libgm, "free_cipher_ctx");
    if (evp_cipher_ctx_free_ptr == NULL) {
        tloge("gmssl not support!\n");
        return;
    }

    evp_cipher_ctx_free_ptr(ctx);
    *ctx = 0;
}

int32_t crypto_sm3_hash(const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (data_in == NULL || data_out == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    struct ctx_handle_t ctx;
    int32_t rc = sm3_digest_init(&ctx);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 hash init failed");
        return CRYPTO_ERROR_SECURITY;
    }

    rc = sm3_digest_update(&ctx, data_in);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 update failed");
        TEE_Free((void *)(uintptr_t)(ctx.ctx_buffer));
        return rc;
    }
    rc = sm3_digest_dofinal(&ctx, data_out);
    if (rc != CRYPTO_SUCCESS)
        tloge("sm3 dofinal failed");

    return rc;
}

int32_t crypto_sm3_hmac(const struct symmerit_key_t *key, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (key == NULL || data_in == NULL || data_out == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    struct ctx_handle_t ctx;

    int32_t rc = sm3_mac_init(&ctx, key);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 hmac init failed");
        return CRYPTO_ERROR_SECURITY;
    }

    rc = sm3_mac_update(&ctx, data_in);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 hmac init failed");
        TEE_Free((void *)(uintptr_t)(ctx.ctx_buffer));
        return CRYPTO_ERROR_SECURITY;
    }

    rc = sm3_mac_computefinal(&ctx, data_out);
    if (rc != CRYPTO_SUCCESS)
        tloge("sm3 hmac dofinal failed");

    return rc;
}

int32_t gm_ae_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param)
{
    bool check = (ctx == NULL || key == NULL || key->key_buffer == 0 || key->key_size == 0);
    int32_t ret = check_and_open_gm(check);
    if (ret != CRYPTO_SUCCESS)
        return ret;
    void *(*libgm_ae_init_ptr)(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
        const struct memref_t *iv) = NULL;
    libgm_ae_init_ptr = dlsym(g_libgm, "libgm_ae_init");
    if (libgm_ae_init_ptr == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    struct memref_t iv = { 0 };
    iv.buffer = ae_init_param->nonce;
    iv.size = ae_init_param->nonce_len;
    void *ae_ctx = libgm_ae_init_ptr(ctx->alg_type, ctx->direction, key, &iv);
    if (ae_ctx == NULL) {
        tloge("ae init failed\n");
        return get_soft_crypto_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    ctx->ctx_buffer = (uint64_t)(uintptr_t)ae_ctx;
    ctx->tag_len = ae_init_param->tag_len;
    ctx->free_context = free_sm4_context;
    return CRYPTO_SUCCESS;
}

int32_t gm_ae_update_aad(struct ctx_handle_t *ctx, const struct memref_t *aad_data)
{
    bool check = (ctx == NULL) || (aad_data == NULL);
    int32_t ret = check_and_open_gm(check);
    if (ret != CRYPTO_SUCCESS)
        return ret;
    int32_t (*libgm_ae_update_aad_ptr)(struct ctx_handle_t *ctx, const struct memref_t *aad_data) = NULL;
    libgm_ae_update_aad_ptr = dlsym(g_libgm, "libgm_ae_update_aad");
    if (libgm_ae_update_aad_ptr == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    return libgm_ae_update_aad_ptr(ctx, aad_data);
}

int32_t gm_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (ctx == NULL) || (data_in == NULL) || (data_out == NULL);
    int32_t ret = check_and_open_gm(check);
    if (ret != CRYPTO_SUCCESS)
        return ret;
    int32_t (*libgm_ae_update_ptr)(struct ctx_handle_t *ctx, const struct memref_t *data_in,
        struct memref_t *data_out) = NULL;
    libgm_ae_update_ptr = dlsym(g_libgm, "libgm_ae_update");
    if (libgm_ae_update_ptr == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    return libgm_ae_update_ptr(ctx, data_in, data_out);
}

int32_t gm_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out)
{
    bool check = (ctx == NULL) || (data_in == NULL) || (data_out == NULL) || (tag_out == NULL);
    int32_t ret = check_and_open_gm(check);
    if (ret != CRYPTO_SUCCESS)
        return ret;
    int32_t (*libgm_ae_enc_final_ptr)(struct ctx_handle_t *ctx, const struct memref_t *data_in,
        struct memref_t *data_out, struct memref_t *tag_out) = NULL;
    libgm_ae_enc_final_ptr = dlsym(g_libgm, "libgm_ae_enc_final");
    if (libgm_ae_enc_final_ptr == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    return libgm_ae_enc_final_ptr(ctx, data_in, data_out, tag_out);
}

int32_t gm_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out)
{
    bool check = (ctx == NULL) || (data_in == NULL) || (data_out == NULL) || (tag_in == NULL);
    int32_t ret = check_and_open_gm(check);
    if (ret != CRYPTO_SUCCESS)
        return ret;
    int32_t (*libgm_ae_dec_final_ptr)(struct ctx_handle_t *ctx, const struct memref_t *data_in,
        const struct memref_t *tag_in, struct memref_t *data_out) = NULL;
    libgm_ae_dec_final_ptr = dlsym(g_libgm, "libgm_ae_dec_final");
    if (libgm_ae_dec_final_ptr == NULL) {
        tloge("gmssl not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    return libgm_ae_dec_final_ptr(ctx, data_in, tag_in, data_out);
}

