/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: Tee defined header file.
 * Author: SDK
 * Create: 2020-03-02
 * History:
 */

#ifndef __TEE_DRV_NPU_DEFINE_H__
#define __TEE_DRV_NPU_DEFINE_H__

#include "hi_type_dev.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_common.h"
#include "hi_bitmap.h"
#include "tee_npu_utils.h"
#include "tee_drv_ioctl_npu.h"

/* structure definition */
typedef struct {
    hi_u32 cmd;
    hi_s32(*fun_entry)(hi_void *arg);
} npu_ioctl_entry;

typedef struct {
    hi_u32                      io_base;
    npu_ioctl_entry             *npu_ioctl_entry;
}tee_npu_mgmt;

#endif      /* __TEE_DRV_NPU_DEFINE_H__ */
