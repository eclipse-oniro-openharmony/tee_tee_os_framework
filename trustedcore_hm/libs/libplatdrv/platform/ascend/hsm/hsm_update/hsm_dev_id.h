/*
* Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
* Description: dev id header file
* Author: huawei
* Create: 2021/9/23
*/
#ifndef HSM_DEV_ID_H
#define HSM_DEV_ID_H

#include <stdint.h>

#define DEV_NUM_MAX 2U
#define DEV_NUM_1 1
#define DEV_NUM_2 2

#define SYSCTRL_REG_BASE 0x80000000U
#define SYSCTRL_REG_SIZE (1024 * 512)

#define SC_PAD_INFO_OFFSET 0xE08C

uint32_t secure_get_dev_num(uint32_t *dev_num);

uint32_t drv_dev_num_init(void);

uint32_t drv_dev_id_verify(uint32_t dev_id);

#endif
