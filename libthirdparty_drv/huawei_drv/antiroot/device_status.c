/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Init function in device
 * Author: wangxiao wangxiao73@huawei.com
 * Create: 2020-02-20
 */
#include "device_status.h"
#include <register_ops.h>
#include <mem_page_ops.h>
#include <sre_log.h>
#include "platdrv.h"
#include "boot_sharedmem.h"

#if (TRUSTEDCORE_PLATFORM_CHOOSE == WITH_HIGENERIC_PLATFORM)
#define STAT_RISK_MAGIC 0x55aa00u
#define STAT_SAFE_MAGIC 0xaa5500u
#define ROOT_STAT_MASK  0xff0000ffu

int32_t is_device_rooted(void)
{
    uint32_t root_flag;
    int32_t ret;

    ret = get_shared_mem_info(TEEOS_SHARED_MEM_ROOT_STATUS, &root_flag, sizeof(uint32_t));
    if (ret != DRV_CALL_OK) {
        tloge("error failed to get shared mem info\n");
        return DEVICE_NOT_ROOTED;
    }

    if (root_flag == (ROOT_STAT_MASK | STAT_RISK_MAGIC)) {
        tlogi("device is in risk mode: have been rooted\n");
        return DEVICE_IS_ROOTED;
    }

    if (root_flag == (ROOT_STAT_MASK | STAT_SAFE_MAGIC)) {
        tlogi("device is in safe mode: have not been rooted\n");
        return DEVICE_NOT_ROOTED;
    }

    tloge("this platform does not support root check, maybe root flag is in wrong format\n");

    return DRV_CALL_ERROR;
}
#else
int32_t is_device_rooted(void)
{
    printf("error this platform does not support root check\n");
    return DRV_CALL_ERROR;
}
#endif
