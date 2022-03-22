/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: sec crypto hal
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */

#include <securec.h>
#include <sre_log.h>
#include "drv_module.h"
#include "crypto_driver_adaptor.h"
#include "trng_api.h"

#define DERIVE_KEY_MAX_OUT  64
#define ROOT_KEY_SIZE       32

static int32_t generate_random(void *rnd, size_t rnd_len)
{
    int32_t ret = trng_get_random(rnd, (uint32_t)rnd_len);
    if (ret != 0)
        return CRYPTO_BAD_PARAMETERS;
    return CRYPTO_SUCCESS;
}

static int32_t derive_root_key(uint32_t derive_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    int32_t ret;
    (void)derive_type;
    (void)data_in;
    if ((data_out == NULL) || ((void *)(uintptr_t)(data_out->buffer) == NULL) || (data_out->size > DERIVE_KEY_MAX_OUT))
        return CRYPTO_BAD_PARAMETERS;

    ret = memset_s((void *)(uintptr_t)(data_out->buffer), data_out->size, 0xab, data_out->size);
    if (ret != EOK)
        return CRYPTO_BAD_STATE;

    return CRYPTO_SUCCESS;
}

const static struct crypto_ops_t g_crypto_ops = {
    .generate_random = generate_random,
    .derive_root_key = derive_root_key,
};

static int32_t qemu_adapt_init(void)
{
    return register_crypto_ops(SEC_CRYPTO_FLAG, &g_crypto_ops);
}

DECLARE_TC_DRV(
    crypto_qemu_adapt,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    qemu_adapt_init,
    NULL,
    NULL,
    NULL,
    NULL
);
