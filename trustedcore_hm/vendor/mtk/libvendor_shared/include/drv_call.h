/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mtk driver framework api for ta
 * Author: HeYanhong heyanhong2@huawei.com
 * Create: 2020-10-12
 */
#ifndef LIBVENDOR_SHARED_DRV_CALL_H
#define LIBVENDOR_SHARED_DRV_CALL_H
#include <stdint.h>
#include "tee_log.h"

#define CALL_DRV_OPEN 0x10U
#define CALL_DRV_IOCTL 0x20U
#define CALL_DRV_CLOSE 0x30U

#define MDRV_MODULE_ID_0 0x9800
#define MDRV_MODULE_ID_1 0x9801
#define MDRV_MODULE_ID_2 0x9802
#define MDRV_MODULE_ID_3 0x9803
#define MDRV_MODULE_ID_4 0x9804
#define MDRV_MODULE_ID_5 0x9805
#define MDRV_MODULE_ID_6 0x9806
#define MDRV_MODULE_ID_7 0x9807
#define MDRV_MODULE_ID_8 0x9808
#define MDRV_MODULE_ID_9 0x9809
#define MDRV_MODULE_ID_10 0x980a
#define MDRV_MODULE_ID_11 0x980b
#define MDRV_MODULE_ID_12 0x980c
#define MDRV_MODULE_ID_13 0x980d
#define MDRV_MODULE_ID_14 0x980e
#define MDRV_MODULE_ID_15 0x980f

#define M_CNT_FREQUENCE 1000U

int32_t mdrv_open(uint32_t driver_id, const void *param);
int32_t mdrv_ioctl(int32_t handle, uint32_t cmd_id, const void *param);
int32_t mdrv_close(int32_t handle);

uint64_t msee_ta_get_cntvct(void);
uint32_t msee_ta_get_cntfrq(void);

#define msee_ta_printf tloge
#define msee_ta_loge tloge
#define msee_ta_logd tlogd

#endif
