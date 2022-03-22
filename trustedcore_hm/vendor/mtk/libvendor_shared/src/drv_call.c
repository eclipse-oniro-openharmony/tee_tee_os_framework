/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mtk driver framework api for ta
 * Author: HeYanhong heyanhong2@huawei.com
 * Create: 2020-10-12
 */
#include "drv_call.h"
#include <stdint.h>
#include "hm_msg_type.h" /* for ARRAY_SIZE */
#include "hmdrv.h"
#include "timer_export.h"

int32_t mdrv_open(uint32_t driver_id, const void *param)
{
    uint64_t args[] = {
        CALL_DRV_OPEN,
        (uintptr_t)param,
    };

    return hm_drv_multithread_call(driver_id, args, ARRAY_SIZE(args));
}

int32_t mdrv_ioctl(int32_t handle, uint32_t cmd_id, const void *param)
{
    uint64_t args[] = {
        CALL_DRV_IOCTL,
        cmd_id,
        (uintptr_t)param,
    };

    /* handle declare which drv module */
    return hm_drv_multithread_call(handle, args, ARRAY_SIZE(args));
}

int32_t mdrv_close(int32_t handle)
{
    uint64_t args[] = {
        CALL_DRV_CLOSE,
    };

    /* handle declare which drv module */
    return hm_drv_multithread_call(handle, args, ARRAY_SIZE(args));
}

uint64_t msee_ta_get_cntvct(void)
{
    return __SRE_ReadTimestamp();
}

__attribute__((weak)) uint32_t msee_ta_get_cntfrq(void)
{
    return M_CNT_FREQUENCE;
}
