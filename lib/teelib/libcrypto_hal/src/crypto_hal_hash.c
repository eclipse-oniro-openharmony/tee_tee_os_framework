/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Hash Crypto API at driver adaptor.
 * Create: 2020-12-21
 */
#include "crypto_hal_hash.h"
#include <tee_log.h>
#include <tee_crypto_hal.h>
#include "crypto_manager.h"
#include "crypto_hal.h"
#include "soft_hash.h"

struct ctx_handle_t *tee_crypto_hash_init(uint32_t alg_type, uint32_t engine)
{
    int32_t ret;
    struct ctx_handle_t *ctx = alloc_ctx_handle(alg_type, engine);
    if (ctx == NULL) {
        tloge("Malloc ctx handle failed\n");
        return NULL;
    }

    if (engine == SOFT_CRYPTO)
        ret = soft_crypto_hash_init(ctx);
    else
        ret = crypto_driver_hash_init(ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Hash init failed, ret=%d\n", ret);
        tee_crypto_ctx_free(ctx);
        return NULL;
    }

    return ctx;
}

int32_t tee_crypto_hash_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    bool check = ((ctx == NULL) || (data_in == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->engine == SOFT_CRYPTO)
        return soft_crypto_hash_update(ctx, data_in);

    return crypto_driver_hash_update(ctx, data_in);
}

int32_t tee_crypto_hash_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = ((ctx == NULL) || (data_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t rc = CRYPTO_SUCCESS;
    check = (data_in != NULL && data_in->buffer != 0 && data_in->size != 0);
    if (check)
        rc = tee_crypto_hash_update(ctx, data_in);

    if (rc != CRYPTO_SUCCESS) {
        tloge("hash do update failed");
        return rc;
    }

    if (ctx->engine == SOFT_CRYPTO)
        return soft_crypto_hash_dofinal(ctx, data_out);

    return crypto_driver_hash_dofinal(ctx, NULL, data_out);
}

int32_t tee_crypto_hash(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    bool check = ((data_in == NULL) || (data_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (engine == SOFT_CRYPTO)
        return soft_crypto_hash(alg_type, data_in, data_out);

    return crypto_driver_hash(alg_type, data_in, data_out, engine);
}
