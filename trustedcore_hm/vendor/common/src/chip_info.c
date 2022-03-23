/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: functions to get chip info
 * Create: 2020-4-6
 */
#include "chip_info.h"
#include <stdint.h>
#include "tee_defines.h"
#include "tee_bit_ops.h"

__attribute__((weak, __visibility__("default"))) int32_t __tee_hal_get_dieid(uint32_t *in_buffer)
{
    (void)in_buffer;
    return TEE_ERROR_NOT_SUPPORTED;
}
