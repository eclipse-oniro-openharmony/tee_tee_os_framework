/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee drv npu utils head file
 * Author: sdk
 * Create: 2020-02-19
 */

#ifndef __TEE_DRV_NPU_UTILS_H__
#define __TEE_DRV_NPU_UTILS_H__

#include "tee_drv_npu_define.h"
#include "tee_drv_os_hal.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define TEE_NPU_ENTER()    hi_tee_drv_hal_printf("%s enter\n", __FUNCTION__);
#define TEE_NPU_EXIT()     hi_tee_drv_hal_printf("%s exit\n", __FUNCTION__);

#define HI_LOG_CHECK(fnFunc)               HI_CHECK(fnFunc)

#define NPU_DRV_PRINTF(fmt...)        hi_tee_drv_hal_printf(fmt)


#define EXPORT_SYMBOL(x)

#define msleep(x) hi_tee_drv_hal_msleep(x)
#define udelay(x) hi_tee_drv_hal_udelay(x)


/* general interface */
tee_npu_mgmt *get_npu_mgmt(hi_void);
void npu_mutex_init(struct hi_tee_hal_mutex *lock);
void npu_mutex_deinit(struct hi_tee_hal_mutex *lock);
void npu_mutex_lock(struct hi_tee_hal_mutex *lock);
void npu_mutex_unlock(struct hi_tee_hal_mutex *lock);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __TEE_DRV_NPU_UTILS_H__ */
