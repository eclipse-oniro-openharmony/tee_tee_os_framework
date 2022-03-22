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
#include "hi_sec_api.h"
#include "sec_adapt.h"

static int32_t generate_random(void *rnd, size_t rnd_len)
{
    if (rnd == NULL)
        return CRYPTO_BAD_PARAMETERS;

    int32_t ret = hi_sec_gen_trng(rnd, (uint32_t)rnd_len);
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

    errno_t ret_s;
    int32_t ret;

    struct hi_sec_kdf_internal para = {0};
    para.iter = HI_KDF_ITER_COUNT;

    ret_s = memcpy_s(para.key, HI_KDF_PASSWD_LEN, (const void*)(uintptr_t)(data_in->buffer), data_in->size);
    if (ret_s != EOK) {
        tloge("Failed to copy the salt to sec\n");
        return CRYPTO_ERROR_SECURITY;
    }

    ret = hi_kdf_to_store(&para);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Failed to derive key from sec\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    ret_s = memcpy_s((void*)(uintptr_t)(data_out->buffer), data_out->size, para.dk, HI_KDF_DK_LEN);
    if (ret_s != EOK) {
        tloge("Failed to copy the key\n");
        return CRYPTO_ERROR_SECURITY;
    }

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
    0,
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
