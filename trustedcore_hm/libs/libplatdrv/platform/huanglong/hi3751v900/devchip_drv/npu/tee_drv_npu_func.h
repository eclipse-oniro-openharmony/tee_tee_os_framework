/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: tee drv npu function head file
 * Author: sdk
 * Create: 2020-03-03
 */

#ifndef __TEE_DRV_NPU_FUNC_H__
#define __TEE_DRV_NPU_FUNC_H__

#include "tee_drv_npu_define.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* for tee npu api interface */
hi_s32 tee_drv_npu_init(hi_void *argp);
hi_s32 tee_drv_npu_deinit(hi_void *argp);
hi_s32 npu_drv_mod_init(hi_void);
hi_s32 npu_drv_mod_exit(hi_void);
hi_s32 tee_drv_npu_test_hwts(hi_void *argp);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __TEE_DRV_NPU_FUNC_H__ */
