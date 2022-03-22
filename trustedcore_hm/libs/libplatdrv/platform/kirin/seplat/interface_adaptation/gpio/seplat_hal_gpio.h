/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: Provides abstract GPIO interfaces for seplat.
 * Create: 2020/12/05
 */
#ifndef HAL_GPIO_H
#define HAL_GPIO_H

#define DELAY_TIME_GPIO 500
#define DELAY_TIME_PWT  25000

#include "stdint.h"

enum seplat_hal_gpio_errno {
    SEPLAT_HAL_ERRCODE_GPIO_DIRECTION      = 0x01,
};

enum hal_gpio_direction {
    HAL_GPIO_INPUT  = 0,
    HAL_GPIO_OUTPUT = 1,
};

enum hal_gpio_value {
    HAL_GPIO_LOW_VALUE  = 0,
    HAL_GPIO_HIGH_VALUE = 1,
};

/*
 * @param gpio_id : gpio num defined by platform.
 * @param direction : set gpio input or output
 * @return SEPLAT_OK if success, other if failed.
 */
int32_t hal_gpio_set_direction(uint32_t gpio_id, enum hal_gpio_direction direction);

/*
 * @param gpio_id : gpio num defined by platform.
 * @param direction : set gpio input high or low.
 * @return SEPLAT_OK if success, other if failed.
 */
int32_t hal_gpio_set_value(uint32_t gpio_id, enum hal_gpio_value value);

int32_t hal_gpio_set_mode(uint32_t gpio_id, uint32_t mode);

#endif
