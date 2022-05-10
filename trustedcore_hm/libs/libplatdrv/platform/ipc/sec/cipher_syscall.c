/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: trng driver syscall
 * Author: liujunliujunliujun.liu@huawei.com
 * Create: 2020-07
 */

#include "cipher_syscall.h"
#include <errno.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <param_check.h>
#include <drv_module.h>
#include <hmdrv_stub.h>
#include "cryp_trng.h"
#include "drv_klad.h"
#include "oemkey_driver_hal.h"

#define CIPHER_KEY_SIZE_IN_BYTE 16
#define CIPHER_KEY_SIZE_IN_WORD (CIPHER_KEY_SIZE_IN_BYTE / 4)
uint8_t g_oem_salt[CIPHER_KEY_SIZE_IN_BYTE] = { 0x26, 0x97, 0xd7, 0xc8,
                                                0xdf, 0x7f, 0xeb, 0xe6,
                                                0x2b, 0x24, 0xe5, 0x99,
                                                0x7e, 0xbe, 0xf5, 0x49, };

static int32_t generate_oem_key(char *c_key, char *oemkey)
{
    int32_t ret;
    ret = DRV_Cipher_KladEncryptKey(HI_UNF_CIPHER_KEY_SRC_KLAD_1,
                                    HI_UNF_CIPHER_KLAD_TARGET_AES,
                                    c_key,
                                    oemkey);
    if (ret != HI_SUCCESS) {
        tloge("gen key failed\n");
        (void)memset_s(oemkey, CIPHER_KEY_SIZE_IN_BYTE, 0, CIPHER_KEY_SIZE_IN_BYTE);
        return -1;
    }
    return 0;
}

uint32_t get_provision_key(uint8_t *provision_key, size_t key_size)
{
    if (provision_key == NULL || key_size != CIPHER_KEY_SIZE_IN_BYTE)
        return 1;
    return (uint32_t)get_secinfo_provisionkey(provision_key, key_size);
}

int32_t get_secinfo_provisionkey(uint8_t *pkey, uint32_t len)
{
    int32_t ret;

    if (pkey == NULL || len != CIPHER_KEY_SIZE_IN_BYTE) {
        tloge("param error\n");
        return -1;
    }

    ret = generate_oem_key(g_oem_salt, pkey);

    return ret;
}

int32_t trng_get_random(uint8_t *trng_addr, uint32_t length)
{
    int32_t i;
    int32_t ret;
    uint32_t random;
    uint8_t *tmp = trng_addr;

    if (trng_addr == NULL || length == 0)
        return -1;

    for (i = 0; i < length; i++) {
        ret = cryp_trng_get_random(&random, -1);
        if (ret != HI_SUCCESS) {
            tloge("get rng failed, ret is %x\n", ret);
            (void)memset_s(trng_addr, length, 0, length);
            return -1;
        }
        *tmp = (uint8_t)random;
        tmp++;
    }
    return 0;
}

int32_t trng_get_entropy(uint8_t *trng_addr, uint32_t length)
{
    int32_t i;
    int32_t ret;
    uint32_t random;
    uint8_t *tmp = trng_addr;

    if (trng_addr == NULL || length == 0)
        return -1;

    for (i = 0; i < length; i++) {
        ret = cryp_trng_get_random(&random, -1);
        if (ret != HI_SUCCESS) {
            tloge("get entropy failed, ret is %x\n", ret);
            (void)memset_s(trng_addr, length, 0, length);
            return -1;
        }
        *tmp = (uint8_t)random;
        tmp++;
    }
    return 0;
}

int32_t cipher_derivekey(const uint8_t *pdata_in, size_t data_size, uint32_t key[CIPHER_KEY_SIZE_IN_WORD])
{
    int32_t ret;
    uint32_t salt[CIPHER_KEY_SIZE_IN_WORD] = {0};
    uint32_t s_size = (data_size > sizeof(salt)) ? sizeof(salt) : data_size;

    if (pdata_in == NULL || data_size == 0 || key == NULL) {
        tloge("params error\n");
        return -1;
    }

    if (memcpy_s(salt, sizeof(salt), pdata_in, s_size) != EOK) {
        tloge("copy failed\n");
        return -1;
    }

    ret = DRV_Cipher_KladEncryptKey(HI_UNF_CIPHER_KEY_SRC_KLAD_1,
                                    HI_UNF_CIPHER_KLAD_TARGET_AES,
                                    salt,
                                    key);
    if (ret != HI_SUCCESS)
        tloge("deriveKey failed, ret is %x\n", ret);
    return ret;
}

int cipher_driver_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    int32_t ret = -1;
    if (params == NULL)
        return ret;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_SEC_RND_GENERATEVECTOR, permissions, CC_RNG_GROUP_PERMISSION)
            ACCESS_CHECK_A64(args[0], args[1]);
            ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
            ret = trng_get_random((uint8_t *)(uintptr_t)args[0], args[1]);
            args[0] = (uint32_t)ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_SEC_DERIVEKEY, permissions, CC_KEY_GROUP_PERMISSION)
            ACCESS_CHECK_A64(args[0], args[1]);
            ACCESS_READ_RIGHT_CHECK(args[0], args[1]);
            ACCESS_CHECK_A64(args[2], CIPHER_KEY_SIZE_IN_BYTE);
            ACCESS_WRITE_RIGHT_CHECK(args[2], CIPHER_KEY_SIZE_IN_BYTE);
            ret = cipher_derivekey((uint8_t *)(uintptr_t)args[0],
                                   (uint32_t)args[1],
                                   (uint8_t *)(uintptr_t)args[2]);
            args[0] = ret;
        SYSCALL_END;

        default:
            return -1;
    }

    return 0;
}

static struct oemkey_ops_t g_oemkey_ops = {
    get_provision_key,
};

static int32_t cipher_init(void)
{
    int32_t ret;
    ret = register_oemkey_ops(SEC_OEMKEY_FLAG, &g_oemkey_ops);
    if (ret != 0) {
        tloge("register oem param error\n");
        return ret;
    }
    ret = DRV_KLAD_Init();
    return ret;
}

DECLARE_TC_DRV(
    cipher_syscall_init,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    cipher_init,
    NULL,
    cipher_driver_syscall,
    NULL,
    NULL
);
