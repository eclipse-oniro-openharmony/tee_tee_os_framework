/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: the hal api for itrustee
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#ifndef __TEE_DRV_OS_HAL_H
#define __TEE_DRV_OS_HAL_H

#include "hi_tee_drv_os_hal.h"

#define os_hal_error(format, args...)   hi_tee_drv_hal_printf("[%s][%d][ERROR]"format, __func__, __LINE__, ##args)

/* RNG register */
#define OS_HAL_RNG_DATA_CTRL          (REG_BASE_RNG + 0x200)
#define OS_HAL_RNG_DATA_VAL           (REG_BASE_RNG + 0x204)
#define OS_HAL_RNG_DATA_CNT           (REG_BASE_RNG + 0x208)

#endif  /* __TEE_DRV_OS_HAL_H */
