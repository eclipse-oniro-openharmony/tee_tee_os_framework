/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: soft rand defines
 * Create: 2020-11-25
 */
#include "soft_rand.h"
#include <drv_module.h>
#include <drv_param_type.h>
#include <sre_access_control.h>
#include <sre_syscalls_id.h>
#include <hmdrv_stub.h>
#include <tee_log.h>
#include <securec.h>
#include <crypto_driver_adaptor.h>

static int random_api_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_CC_CRYS_RND_GENERATEVECTOR, permissions, CC_RNG_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[0]);
        ACCESS_WRITE_RIGHT_CHECK(args[1], args[0]);
        ret = get_rands((uint32_t)args[0], (uint8_t *)(uintptr_t)args[1]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_CRYPTO_GENERATE_RANDOM, permissions, CC_RNG_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
        ret = get_rands((uint32_t)args[1], (uint8_t *)(uintptr_t)args[0]);
        args[0] = ret;
        SYSCALL_END;

    default:
        return -1;
    }

    return 0;
}

DECLARE_TC_DRV(
    soft_rand_adapt,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    soft_crypto_init,
    NULL,
    random_api_syscall,
    NULL,
    NULL
);

