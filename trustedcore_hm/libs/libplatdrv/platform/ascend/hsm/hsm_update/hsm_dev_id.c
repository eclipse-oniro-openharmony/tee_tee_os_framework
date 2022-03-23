/*
* Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
* Description: dev id source file
* Author: huawei
* Create: 2021/9/23
*/
#include "register_ops.h"
#include "tee_defines.h"
#include "tee_log.h"
#include "tee_log.h"
#include "tee_bit_ops.h"

#include "driver_common.h"
#include "hsm_dev_id.h"

static uint32_t g_dev_id_max = 0;

uint32_t drv_dev_id_verify(uint32_t dev_id)
{
    if (dev_id > g_dev_id_max) {
        tloge("dev id is invaild %d.\n", dev_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

uint32_t secure_get_dev_num(uint32_t *dev_num)
{
    uint32_t val;

    if (dev_num == NULL) {
        tloge("Invalid parms.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    val = read32(SYSCTRL_REG_BASE + SC_PAD_INFO_OFFSET);
    val &= BIT5;

    *dev_num = (val == BIT5) ? DEV_NUM_2 : DEV_NUM_1;

    return TEE_SUCCESS;
}

uint32_t drv_dev_num_init(void)
{
    uint32_t dev_num = 0;
    uint32_t ret;

    ret = secure_get_dev_num(&dev_num);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    g_dev_id_max = (dev_num > 1) ? 1 : 0;

    return TEE_SUCCESS;
}
