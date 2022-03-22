/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.
 * Description: device key wrapper implementation
 * Create: 2018-05-18
 */
#include <dlfcn.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_crypto_hal.h>
#include <crypto_hal_hmac.h>
#include <crypto_hal_hash.h>
#include <tee_internal_huk_api.h>
#include <oemkey.h>
#include "crypto_inner_interface.h"

static int32_t get_derived_key(uint8_t *tmp_key,  uint8_t *priv, uint32_t priv_len)
{
    struct memref_t data_in = {0};
    struct memref_t data_out = {0};
    uint8_t derived_key[SHA256_LEN] = {0};
    data_in.buffer = (uint64_t)(uintptr_t)tmp_key;
    data_in.size = OEM_KEY_LEN;
    data_out.buffer = (uint64_t)(uintptr_t)derived_key;
    data_out.size = SHA256_LEN;
    (void)tee_crypto_hash(CRYPTO_TYPE_DIGEST_SHA256, &data_in, &data_out, SOFT_CRYPTO);

    errno_t ret_s = memcpy_s(priv, priv_len, derived_key, SHA256_LEN);
    (void)memset_s(derived_key, SHA256_LEN, 0, SHA256_LEN);
    if (ret_s != EOK)
        return -1;

    return 0;
}

int32_t get_class_ecc_key(uint8_t *priv, uint32_t priv_len)
{
    uint32_t ret;
    uint8_t tmp_key[OEM_KEY_LEN] = {0};
    bool check = (priv == NULL || priv_len != SHA256_LEN);
    if (check) {
        tloge("invalid parameters\n");
        return -1;
    }

    ret = tee_hal_get_provision_key(tmp_key, OEM_KEY_LEN);
    if (ret) {
        tloge("get provision data failed\n");
        return -1;
    }

    ret = (uint32_t)get_derived_key(tmp_key, priv, priv_len);
    (void)memset_s(tmp_key, OEM_KEY_LEN, 0, OEM_KEY_LEN);
    return (int32_t)ret;
}

#define SALT_LEN    16
static int32_t get_tmp_key(uint8_t *tmp_key, uint32_t *outsize)
{
    uint8_t salt[SALT_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    errno_t ret_s = memset_s(tmp_key, SHA256_LEN, 0x55, SALT_LEN);
    if (ret_s != EOK)
        return -1;

    ret_s = memcpy_s(tmp_key + SALT_LEN, (SHA256_LEN - SALT_LEN), salt, sizeof(salt));
    if (ret_s != EOK)
        return -1;

    int32_t ret = (int32_t)tee_internal_provision_key(tmp_key, outsize);
    if (ret != TEE_SUCCESS) {
        tloge("Provision Key failed\n");
        if (memset_s(tmp_key, SHA256_LEN, 0, SHA256_LEN) != EOK)
            tloge("memory clear fail");
    }
    return ret;
}

static int32_t do_get_huk(const uint8_t *key, uint32_t key_size,
    uint8_t *tmp_key, uint8_t *derived_key, uint8_t *huk)
{
    struct symmerit_key_t key_temp = {0};
    struct memref_t data_in = {0};
    struct memref_t data_out = {0};
    key_temp.key_buffer = (uint64_t)(uintptr_t)key;
    key_temp.key_size = key_size;
    data_in.buffer = (uint64_t)(uintptr_t)tmp_key;
    data_in.size = SHA256_LEN;
    data_out.buffer = (uint64_t)(uintptr_t)derived_key;
    data_out.size = SHA256_LEN;

    int32_t rc = tee_crypto_hmac(CRYPTO_TYPE_HMAC_SHA256, &key_temp, &data_in, &data_out, SOFT_CRYPTO);
    errno_t ret_s  = memset_s(tmp_key, SHA256_LEN, 0, SHA256_LEN);
    bool check = (rc != 0 || ret_s != EOK);
    if (check) {
        tloge("hmac 256 or memset failed\n");
        return -1;
    }

    /* Because we don't know the size of huk,
     * so, the length of huk  should be checked by caller
     */
    (void)memcpy_s(huk, SHA256_LEN, derived_key, SHA256_LEN);
    return 0;
}

/* oem_key + hmac256 */
int32_t get_class_oem_huk(uint8_t *huk, const uint8_t *key, uint32_t key_size)
{
    uint32_t outsize = OEM_KEY_LEN;
    uint8_t tmp_key[SHA256_LEN];
    uint8_t derived_key[SHA256_LEN];
    bool check = (huk == NULL || key == NULL || get_tmp_key(tmp_key, &outsize) != TEE_SUCCESS);
    if (check) {
        tloge("get class oem key failed\n");
        return -1;
    }

    return do_get_huk(key, key_size, tmp_key, derived_key, huk);
}
