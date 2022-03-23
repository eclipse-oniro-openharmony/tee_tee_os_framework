/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: sec crypto hal
 * Create: 2020-10-14
 */
#include <securec.h>
#include <sre_log.h>
#include "drv_module.h"
#include "crypto_driver_adaptor.h"
#include "trng_api.h"
#include "sec_api.h"

#define DERIVE_KEY_MAX_OUT 64

static int32_t generate_random(void *rnd, size_t rnd_len)
{
    uint32_t i;
    uint32_t value;
    uint32_t *tmp_addr = NULL;
    uint32_t left;
    errno_t ret;

    if (rnd == NULL) {
        tloge("bad param!\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    left = rnd_len % WORD_SIZE;
    tmp_addr = (uint32_t *)rnd;

    for (i = 0; i < rnd_len / WORD_SIZE; i++) {
        tmp_addr[i] = read_rng_value((i % WORD_SIZE));
        if (tmp_addr[i] == 0) {
            tloge("get rng value error!\n");
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    if (left == 0)
        return CRYPTO_SUCCESS;

    value = read_rng_value(0);
    ret = memcpy_s(rnd + i * WORD_SIZE, rnd_len - i * WORD_SIZE, (char *)(&value), left);
    if (ret != EOK) {
        tloge("copy random error!\n");
        return CRYPTO_ERROR_SECURITY;
    }

    return CRYPTO_SUCCESS;
}

static int32_t get_entropy(void *rnd, size_t rnd_len)
{
    uint32_t i;
    uint32_t value;
    uint32_t *tmp_addr = NULL;
    uint32_t left;
    errno_t ret;

    if (rnd == NULL)
        return CRYPTO_BAD_PARAMETERS;

    left = rnd_len % WORD_SIZE;
    tmp_addr = (uint32_t *)rnd;

    for (i = 0; i < rnd_len / WORD_SIZE; i++) {
        tmp_addr[i] = read_entropy_value(0);
        if (tmp_addr[i] == 0) {
            tloge("read entropy value error!\n");
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    if (left == 0)
        return CRYPTO_SUCCESS;

    value = read_entropy_value(0);
    ret = memcpy_s(rnd + i * WORD_SIZE, rnd_len - i * WORD_SIZE, (char *)(&value), left);
    if (ret != EOK) {
        tloge("copy entropy error!\n");
        return CRYPTO_ERROR_SECURITY;
    }

    return CRYPTO_SUCCESS;
}

static int derive_root_key(uint32_t derive_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    if ((data_out == NULL) || (data_out->buffer == 0) || (data_out->size > DERIVE_KEY_MAX_OUT))
        return CRYPTO_BAD_PARAMETERS;
    uint32_t ret;

    ret = sec_huk_pbkdf2(derive_type, data_in, data_out);
    if (ret)
        return CRYPTO_BAD_PARAMETERS;

    return CRYPTO_SUCCESS;
}

static struct crypto_ops_t g_crypto_ops = {
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
    get_entropy,
    derive_root_key,
    0,
};

static int32_t sec_adapt_init(void)
{
    uint32_t ret = sec_init();
    if (ret != SEC_SUCCESS) {
        tloge("sec init failed!\n");
        g_crypto_ops.derive_root_key = 0;
    }
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
