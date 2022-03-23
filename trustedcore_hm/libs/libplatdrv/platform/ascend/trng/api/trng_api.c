/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: the api of trng source
* Author: huawei
* Create: 2019/12/30
*/
#include "tee_defines.h"
#include "drv_module.h"
#include "tee_log.h"
#include "sre_access_control.h"
#include "register_ops.h"
#include <hmdrv_stub.h>
#include "sre_syscalls_id.h"
#include "drv_param_type.h"
#include <securec.h>

#include "trng_api.h"
#include "trng_internal_api.h"

uint32_t trng_distribute(uint8_t *scr, uint32_t len)
{
    uint32_t ret;
    uint32_t counts;
    uint32_t remain;
    uint32_t i;
    uint8_t buf[TRNG_NORMAL_LEN];

    if ((scr == NULL) || (len > TRNG_MAX_LEN)) {
        tloge("The trng parameter is wrong!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    counts = len >> RNG_BUFFER_BLSR;
    remain = len & RNG_BUFFER_SIZE_MASK;

    for (i = 0; i < counts; i++) {
        ret = trng_get_data_use(scr + (i << RNG_BUFFER_BLSR), TRNG_NORMAL_LEN);
        if (ret != TRNG_SUCCESS) {
            return ret;
        }
    }

    if (remain != 0) {
        ret = trng_get_data_use((uint8_t *)(uintptr_t)buf, TRNG_NORMAL_LEN);
        if (ret != TRNG_SUCCESS) {
            return ret;
        }

        for (i = 0; i < remain; i++) {
            scr[i + (counts << RNG_BUFFER_BLSR)] = buf[i];
        }
    }

    return TRNG_SUCCESS;
}

uint32_t trng_get_random(uint8_t *trng_addr, uint32_t len)
{
    uint32_t ret;

    ret = trng_distribute(trng_addr, len);
    if (ret != TRNG_SUCCESS) {
        return ret;
    }

    return TRNG_SUCCESS;
}

int trng_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t len;
    uint64_t buf;
    uint64_t *args = NULL;

    if ((params == NULL) || (params->args == 0)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_TRNG_GENERATE_RANDOM, permissions, GENERAL_GROUP_PERMISSION)
        uint32_t ret;
        buf = ((args[1] << SHIFT_LEN_32) | args[0]);
        len = args[RNG_INDEX2];
        ACCESS_CHECK_A64(buf, len);
        ACCESS_WRITE_RIGHT_CHECK(buf, len);
        ret = trng_get_random((uint8_t *)(uintptr_t)buf, len);
        args[0] = ret;
        SYSCALL_END
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TRNG_SUCCESS;
}

DECLARE_TC_DRV(
    trng_hiss_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    trng_syscall,
    NULL,
    NULL);
