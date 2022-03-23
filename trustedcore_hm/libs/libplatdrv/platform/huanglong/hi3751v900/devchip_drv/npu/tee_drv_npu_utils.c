/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee drv npu utils impl.
 * Author: sdk
 * Create: 2020-02-19
 */

#include "hi_type_dev.h"
#include "hi_tee_drv_mem.h"

#include "tee_drv_npu_define.h"
#include "tee_drv_npu_utils.h"

void npu_mutex_init(struct hi_tee_hal_mutex *lock)
{
    hi_s32 ret;
    hi_char str[16] = {0}; /* the max mutex length is 16 bytes. */

    snprintf_s(str, sizeof(str), sizeof(str) - 1, "%p", lock);

    ret = hi_tee_drv_hal_mutex_init(str, lock);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_printf("Create mutex failed, ret[0x%x]\n", ret);
    }
}

void npu_mutex_deinit(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_destroy(lock);
}

void npu_mutex_lock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_lock(lock);
}

void npu_mutex_unlock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_unlock(lock);
}

hi_s32 npu_get_user_uuid(TEE_UUID *pstUUID)
{
    NPU_NULL_POINTER_RETURN(pstUUID);

    return hi_tee_drv_hal_current_uuid(pstUUID);
}

