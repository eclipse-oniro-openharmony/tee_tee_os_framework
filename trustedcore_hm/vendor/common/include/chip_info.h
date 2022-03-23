/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declear functions to get chip info
 * Create: 2020-4-6
 */
#ifndef CHIP_INFO_H
#define CHIP_INFO_H
#include <stdint.h>

int __tee_hal_get_dieid(uint32_t *in_buffer);

#endif
