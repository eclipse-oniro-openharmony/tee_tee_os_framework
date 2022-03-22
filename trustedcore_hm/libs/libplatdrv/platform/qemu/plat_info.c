/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: get plat_infos for qemu_lite platform
 * Author: wangcong wangcong48@huawei.com
 * Create: 2020-11
 */

#include <tee_log.h>
#include "securec.h"
#include "drv_module.h"
#include "oemkey_driver_hal.h"

#define PLAT_INFO_SIZE 16

static uint8_t g_plat_info[PLAT_INFO_SIZE] = { 0xbc, 0x7a, 0x99, 0x82, 0xb2, 0xd, 0x54, 0xb1,
                                               0xa8, 0xf1, 0xc3, 0xf6, 0x36, 0x8, 0x10, 0xc9 };

static uint32_t get_provision_key(uint8_t *info, size_t key_size)
{
    if (info == NULL || key_size != PLAT_INFO_SIZE) {
        tloge("invalid info param\n");
        return 1;
    }

    if (memcpy_s(info, key_size, g_plat_info, PLAT_INFO_SIZE) != EOK) {
        tloge("memcpy failed\n");
        return 1;
    }

    return 0;
}

static struct oemkey_ops_t g_oemkey_ops = {
    get_provision_key,
};

static int32_t plat_info_init(void)
{
    return register_oemkey_ops(SEC_OEMKEY_FLAG, &g_oemkey_ops);
}

DECLARE_TC_DRV(
    qemu_plat_info,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    plat_info_init,
    NULL,
    NULL,
    NULL,
    NULL
);
