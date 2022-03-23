/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: Provides abstract GPIO interfaces for seplat.
 * Create: 2020/12/05
 */
#include "seplat_hal_gpio.h"
#include "seplat_errno.h"
#include "types.h"
#include "gpio.h"

#define SEPLAT_THIS_MODULE SEPLAT_MODULE_HAL_GPIO
#define SEPLAT_ERROR_TAG "[SEPLAT_GPIO]"

/*
 * @param gpio_id : gpio num defined by platform.
 * @param direction : set gpio input or output
 * @return SEPLAT_OK if success, other if failed.
 */
int32_t hal_gpio_set_direction(uint32_t gpio_id, enum hal_gpio_direction direction)
{
    uint32_t dir_cur = gpio_get_direction(gpio_id);

    if (dir_cur == (uint32_t)direction)
        return SEPLAT_OK;

    if (direction == HAL_GPIO_INPUT)
        gpio_set_direction_input(gpio_id);
    else if (direction == HAL_GPIO_OUTPUT)
        gpio_set_direction_output(gpio_id);
    else
        return SEPLAT_ERRCODE(SEPLAT_HAL_ERRCODE_GPIO_DIRECTION);

    return SEPLAT_OK;
}

/*
 * @param gpio_id : gpio num defined by platform.
 * @param direction : set gpio input high or low.
 * @return SEPLAT_OK if success, other if failed.
 */
int32_t hal_gpio_set_value(uint32_t gpio_id, enum hal_gpio_value value)
{
    gpio_set_value(gpio_id, (uint32_t)value);
    return SEPLAT_OK;
}

int32_t hal_gpio_set_mode(uint32_t gpio_id, uint32_t mode)
{
    gpio_set_mode(gpio_id, mode);
    return SEPLAT_OK;
}
