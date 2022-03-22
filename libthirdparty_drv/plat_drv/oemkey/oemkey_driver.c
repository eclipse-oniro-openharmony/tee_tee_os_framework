/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: oemkey driver register
 * Create: 2021-07
 */
#include "drv_module.h"
#include "drv_param_type.h"
#include <hmdrv_stub.h>
#include "oemkey_driver_hal.h"
#include <derive_teekey.h>

uint32_t get_provision_key(uint8_t *provision_key, size_t key_size)
{
    if (key_size != PLAT_TEEKEY_SIZE)
        return 1;
    return plat_derive_teekey(provision_key, (uint32_t)key_size);
}

static struct oemkey_ops_t g_oemkey_ops = {
    get_provision_key,
};

static int32_t oemkey_init(void)
{
    return register_oemkey_ops(SEC_OEMKEY_FLAG, &g_oemkey_ops);
}

DECLARE_TC_DRV(oemkey_driver, 0, 0, 0, TC_DRV_MODULE_INIT, oemkey_init, NULL, NULL, NULL, NULL);
