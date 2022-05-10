/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: implament crypto driver manager
 * Create: 2020-03-24
 */
#include "crypto_manager.h"
#include <stdio.h>
#include <hmdrv.h>
#include <tee_log.h>
#include <securec.h>
#include <sre_syscalls_id.h>
#include "tee_sharemem_ops.h"
#include "tee_drv_client.h"
#include "crypto_hal.h"
#include "tee_mem_mgmt_api.h"
#include "crypto_default_engine.h"
#include "soft_common_api.h"

#define hmccmgr_call_ex(...) hm_drv_call_ex(__VA_ARGS__)
#define hmccmgr_call(...)    hm_drv_call(__VA_ARGS__)

int32_t driver_ctx_buffer_prepare(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx)
{
    if (src_ctx == NULL || dest_ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    uint64_t *ctx_buffer = &(dest_ctx->ctx_buffer);
    int32_t ctx_size = src_ctx->ctx_size;

    if (ctx_buffer == NULL)
        return CRYPTO_BAD_PARAMETERS;

    TEE_Free((void *)(uintptr_t)(*ctx_buffer));
    *ctx_buffer = (uintptr_t)malloc_coherent(ctx_size);
    if (*ctx_buffer == 0) {
        tloge("malloc crypto ctx buffer failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    (void)memset_s((void *)(uintptr_t)(*ctx_buffer), ctx_size, 0, ctx_size);

    return CRYPTO_SUCCESS;
}

struct ctx_handle_t *driver_alloc_ctx_handle(uint32_t alg_type, uint32_t engine, struct ctx_handle_t *ctx)
{
    int32_t ctx_size;
    uint8_t *ctx_ctx_buffer = NULL;
    ctx_size = crypto_driver_get_ctx_size(alg_type, engine);
    bool check = ((ctx_size <= 0) || (ctx_size > MAX_CRYPTO_CTX_SIZE) || ctx == NULL);
    if (check) {
        tloge("Get ctx size failed, ctx size=%d, algorithm type=0x%x, engine=0x%x\n", ctx_size, alg_type, engine);
        goto error;
    }

    ctx_ctx_buffer = (uint8_t *)malloc_coherent((size_t)ctx_size);
    if (ctx_ctx_buffer == NULL) {
        tloge("Malloc ctx buffer failed, ctx size=%d\n", ctx_size);
        goto error;
    }
    if (memset_s(ctx_ctx_buffer, (size_t)ctx_size, 0, (size_t)ctx_size) != EOK) {
        tloge("memset ctx buffer failed\n");
        goto error;
    }
    ctx->driver_ability = (uint32_t)crypto_driver_get_driver_ability(engine);
    ctx->ctx_buffer = (uint64_t)(uintptr_t)ctx_ctx_buffer;
    ctx->ctx_size = (uint32_t)ctx_size;
    return ctx;

error:
    if (ctx_ctx_buffer != NULL) {
        TEE_Free(ctx_ctx_buffer);
        ctx_ctx_buffer = NULL;
    }
    TEE_Free(ctx);
    return NULL;
}

uint32_t crypto_get_default_engine(uint32_t algorithm)
{
    size_t i;
    size_t count = sizeof(g_algorithm_engine) / sizeof(g_algorithm_engine[0]);
    for (i = 0; i < count; i++) {
        if (g_algorithm_engine[i].algorithm == algorithm)
            return g_algorithm_engine[i].engine;
    }
    return SOFT_CRYPTO;
}

uint32_t crypto_get_default_generate_key_engine(uint32_t algorithm)
{
    size_t i;
    size_t count = sizeof(g_generate_key_engine) / sizeof(g_generate_key_engine[0]);
    for (i = 0; i < count; i++) {
        if (g_generate_key_engine[i].algorithm == algorithm)
            return g_generate_key_engine[i].engine;
    }
    return SOFT_CRYPTO;
}

int32_t crypto_driver_get_driver_ability(uint32_t engine)
{
    uint64_t args[] = {
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_GET_DRV_ABILITY, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_get_ctx_size(uint32_t alg_type, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_GET_CTX_SIZE, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ctx_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)src_ctx,
        (uint64_t)(uintptr_t)dest_ctx,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_CTX_COPY, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_hash_init(struct ctx_handle_t *ctx)
{
    if (ctx == NULL)
        return -1;
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_HASH_INIT, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_hash_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)data_in,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_HASH_UPDATE, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_hash_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_HASH_DOFINAL, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_hash(uint32_t alg_type, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_HASH, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_hmac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)key,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_HMAC_INIT, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_hmac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)data_in,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_HMAC_UPDATE, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_hmac_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_HMAC_DOFINAL, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_hmac(uint32_t alg_type, const struct symmerit_key_t *key,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)key,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_HMAC, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_cipher_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct memref_t *iv)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)key,
        (uint64_t)(uintptr_t)iv,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_CIPHER_INIT, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_CIPHER_UPDATE, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_cipher_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_CIPHER_DOFINAL, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_cipher(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        direction,
        (uint64_t)(uintptr_t)key,
        (uint64_t)(uintptr_t)iv,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_CIPHER, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ae_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)key,
        (uint64_t)(uintptr_t)ae_init_param,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_AE_INIT, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ae_update_aad(struct ctx_handle_t *ctx, const struct memref_t *aad_data)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)aad_data,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_AE_UPDATE_AAD, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_AE_UPDATE, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
        (uint64_t)(uintptr_t)tag_out,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_AE_ENC_FINAL, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)ctx,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)tag_in,
        (uint64_t)(uintptr_t)data_out,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_AE_DEC_FINAL, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_rsa_generate_keypair(uint32_t key_size, const struct memref_t *e_value, bool crt_mode,
    struct rsa_priv_key_t *key_pair, uint32_t engine)
{
    uint64_t args[] = {
        (uint64_t)key_size,
        (uint64_t)(uintptr_t)e_value,
        (uint64_t)crt_mode,
        (uint64_t)(uintptr_t)key_pair,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_RSA_GENERATE_KEYPAIR, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_rsa_encrypt(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)public_key,
        (uint64_t)(uintptr_t)rsa_params,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_RSA_ENCRYPT, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_rsa_decrypt(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in, struct memref_t *data_out,
    uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)private_key,
        (uint64_t)(uintptr_t)rsa_params,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_RSA_DECRYPT, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params,
    const struct memref_t *digest, struct memref_t *signature, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)private_key,
        (uint64_t)(uintptr_t)rsa_params,
        (uint64_t)(uintptr_t)digest,
        (uint64_t)(uintptr_t)signature,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_RSA_SIGN_DIGEST, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params,
    const struct memref_t *digest, const struct memref_t *signature, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)public_key,
        (uint64_t)(uintptr_t)rsa_params,
        (uint64_t)(uintptr_t)digest,
        (uint64_t)(uintptr_t)signature,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_RSA_VERIFY_DIGEST, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ecc_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key, uint32_t engine)
{
    uint64_t args[] = {
        key_size,
        curve,
        (uint64_t)(uintptr_t)public_key,
        (uint64_t)(uintptr_t)private_key,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_ECC_GENERATE_KEYPAIR, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)public_key,
        (uint64_t)(uintptr_t)ec_params,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_ECC_ENCRYPT, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)private_key,
        (uint64_t)(uintptr_t)ec_params,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_ECC_DECRYPT, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *digest, struct memref_t *signature, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)private_key,
        (uint64_t)(uintptr_t)ec_params,
        (uint64_t)(uintptr_t)digest,
        (uint64_t)(uintptr_t)signature,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_ECC_SIGN_DIGEST, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *digest, const struct memref_t *signature, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)public_key,
        (uint64_t)(uintptr_t)ec_params,
        (uint64_t)(uintptr_t)digest,
        (uint64_t)(uintptr_t)signature,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_ECC_VERIFY_DIGEST, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_ecdh_derive_key(uint32_t alg_type,
    const struct ecc_pub_key_t *client_key, const struct ecc_priv_key_t *server_key,
    const struct asymmetric_params_t *ec_params, struct memref_t *secret, uint32_t engine)
{
    uint64_t args[] = {
        alg_type,
        (uint64_t)(uintptr_t)client_key,
        (uint64_t)(uintptr_t)server_key,
        (uint64_t)(uintptr_t)ec_params,
        (uint64_t)(uintptr_t)secret,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_ECDH_DERIVE_KEY, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_dh_generate_key(const struct dh_key_t *dh_generate_key_data,
    struct memref_t *pub_key, struct memref_t *priv_key, uint32_t engine)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)dh_generate_key_data,
        (uint64_t)(uintptr_t)pub_key,
        (uint64_t)(uintptr_t)priv_key,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_DH_GENERATE_KEY, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_dh_derive_key(const struct dh_key_t *dh_derive_key_data,
    struct memref_t *secret, uint32_t engine)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)dh_derive_key_data,
        (uint64_t)(uintptr_t)secret,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_DH_DERIVE_KEY, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_generate_random(void *buffer, uint32_t size, bool is_hw_rand)
{
    if (is_hw_rand) {
        uint64_t args[] = {
            (uint64_t)(uintptr_t)buffer,
            (uint64_t)size,
        };

        return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_GENERATE_RANDOM, args, ARRAY_SIZE(args));
    } else {
#ifdef OPENSSL_ENABLE
        return get_openssl_rand(buffer, size);
#else
        return CRYPTO_NOT_SUPPORTED;
#endif
    }
}

int32_t crypto_driver_get_entropy(void *buffer, uint32_t size)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)buffer,
        (uint64_t)size,
    };
#if !defined(TEE_SUPPORT_PLATDRV_64BIT) && !defined(TEE_SUPPORT_PLATDRV_32BIT)
    (void)args;
    return soft_random_get(buffer, size);
#else
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_GET_ENTROPY, args, ARRAY_SIZE(args));
#endif
}

int32_t crypto_driver_derive_root_key(uint32_t derive_type,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t iter_num)
{
    uint64_t args[] = {
        derive_type,
        (uint64_t)(uintptr_t)data_in,
        (uint64_t)(uintptr_t)data_out,
        iter_num,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_DERIVE_ROOT_KEY, args, ARRAY_SIZE(args));
}

int32_t crypto_driver_pbkdf2(const struct memref_t *password, const struct memref_t *salt, uint32_t iterations,
    uint32_t digest_type, struct memref_t *data_out, uint32_t engine)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)password,
        (uint64_t)(uintptr_t)salt,
        iterations,
        digest_type,
        (uint64_t)(uintptr_t)data_out,
        engine,
    };
    return (int32_t)hmccmgr_call(SW_SYSCALL_CRYPTO_PBKDF2, args, ARRAY_SIZE(args));
}
int32_t tee_crypto_check_alg_support(uint32_t alg_type)
{
    (void)alg_type;
    return CRYPTO_NOT_SUPPORTED;
}
