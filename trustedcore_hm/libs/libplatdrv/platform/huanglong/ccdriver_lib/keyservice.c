/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keyservice syscall
 * Create: 2020-11-02
 */

#include "drv_module.h"
#include "oemkey_driver_hal.h"

#define SIZE_KOEM              16
#define HIGH_ADDRESS_OFFSET    32
uint32_t get_provision_key(uint8_t *provision_key, size_t key_size);

static struct oemkey_ops_t g_oemkey_ops = {
    get_provision_key,
};

static int32_t keyservice_init(void)
{
    return register_oemkey_ops(SEC_OEMKEY_FLAG, &g_oemkey_ops);
}

DECLARE_TC_DRV(
    keyservice_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    keyservice_init,
    NULL,
    NULL,
    NULL,
    NULL
);
