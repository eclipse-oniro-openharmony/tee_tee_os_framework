/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: platform_get && chip_get header files
 * Create: 2021-04
 */

#ifndef DRV_PLATFORM_GET_H
#define DRV_PLATFORM_GET_H

#include <stdint.h>

int __get_platform_chip(uint32_t *platform, uint32_t *chip);
int __get_target_product(char *target_product, int *buff_size);

#endif
