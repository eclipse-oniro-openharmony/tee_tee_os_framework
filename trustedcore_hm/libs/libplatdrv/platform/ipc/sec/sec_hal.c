/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: sec crypto hal
 * Author: Jia Lingyu jialingyu@huawei.com
 * Create: 2020-10-14
 */
#include <securec.h>
#include <sre_log.h>
#include "drv_module.h"
#include "crypto_driver_adaptor.h"
#include "cipher_syscall.h"
static int32_t generate_random(void *rnd, size_t rnd_len)
{
    int32_t ret = trng_get_random(rnd, (uint32_t)rnd_len);
    if (ret != CRYPTO_SUCCESS)
        return CRYPTO_BAD_PARAMETERS;
    return CRYPTO_SUCCESS;
}

static int32_t get_entropy(void *rnd, size_t rnd_len)
{
    int32_t ret = trng_get_entropy(rnd, (uint32_t)rnd_len);
    if (ret != CRYPTO_SUCCESS)
        return CRYPTO_BAD_PARAMETERS;
    return CRYPTO_SUCCESS;
}

static int derive_root_key(uint32_t derive_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)derive_type;
    if (data_in == NULL || data_in->buffer == 0 ||
        data_out == NULL || data_out->buffer == 0)
        return CRYPTO_BAD_PARAMETERS;

    int32_t ret = cipher_derivekey((const uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint32_t *)(uintptr_t)(data_out->buffer));
    if (ret != CRYPTO_SUCCESS) {
        tloge("Failed to derive key!");
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = CIPHER_KEY_SIZE_IN_BYTE;
    return CRYPTO_SUCCESS;
}

const static struct crypto_ops_t g_crypto_ops = {
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
