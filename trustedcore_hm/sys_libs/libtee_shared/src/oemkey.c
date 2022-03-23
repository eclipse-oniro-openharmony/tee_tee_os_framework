/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: oemkey interface
 * Create: 2021-7-19
 */

#include <stdint.h>
#include <hmdrv.h>
#include <hm_msg_type.h> /* for ARRAY_SIZE */
#include <sre_syscalls_id.h>
#include "securec.h"
#include "tee_defines.h"
#include "tee_sharemem.h"
#include "tee_log.h"

#ifdef CONFIG_QEMU_LITE_PLAT
#define PLAT_INFO_SIZE 16
static uint8_t g_plat_info[PLAT_INFO_SIZE] = { 0xbc, 0x7a, 0x99, 0x82, 0xb2, 0xd, 0x54, 0xb1,
                                               0xa8, 0xf1, 0xc3, 0xf6, 0x36, 0x8, 0x10, 0xc9 };
#endif

__attribute__((visibility("default"))) \
uint32_t tee_hal_get_provision_key(uint8_t *oem_key, size_t key_size)
{
#ifdef CONFIG_TEE_MISC_DRIVER
    uint32_t ret = tee_get_oemkey_info(oem_key, key_size);
    return ret;
#else
#ifdef CONFIG_QEMU_LITE_PLAT
    if (oem_key == NULL || key_size != PLAT_INFO_SIZE)
        return 1;

    if (memcpy_s(oem_key, key_size, g_plat_info, PLAT_INFO_SIZE) != EOK)
        return 1;

    return 0;
#else
    uint64_t args[] = {
        (uint64_t)(uintptr_t)(oem_key),
        (uint64_t)key_size,
    };
    return hm_drv_call(SW_SYSCALL_GET_PROVISION_KEY, args, ARRAY_SIZE(args));
#endif
#endif
}
