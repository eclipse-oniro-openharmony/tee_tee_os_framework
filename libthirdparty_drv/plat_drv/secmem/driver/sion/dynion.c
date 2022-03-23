/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: dynion driver func
 * Create: 2019-12-20
 */

#include "dynion.h"      /* struct sglist */
#include <drv_module.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <sec_region_ops.h>
#include <hmdrv_stub.h> /* keep this last */

#define SEC_FEATURE_OFFSET 8
#define DDR_CFG_TYPE_BITS  0xFF

static int32_t set_dynmem_config(struct sglist *sglist, int32_t type)
{
    int32_t ret = HM_ERROR;

    if (sglist == NULL) {
        tloge("sglist is NULL\n");
        return ret;
    }

    ret = ddr_sec_cfg(sglist, (enum SEC_FEATURE)((uint32_t)type >> SEC_FEATURE_OFFSET),
                      (DDR_CFG_TYPE)((uint32_t)type & DDR_CFG_TYPE_BITS));
    uart_printf_func("set dynmem config size=%u, type=%d, ret=%d\n", (uint32_t)sglist->ion_size, type, ret);

    return ret;
}

static int32_t check_sglist(struct sglist *tmp_sglist)
{
    if (UINT64_MAX - sizeof(*tmp_sglist) < (sizeof(TEE_PAGEINFO) * (tmp_sglist->infoLength)))
        return HM_ERROR;

    if (tmp_sglist->sglistSize != (sizeof(*tmp_sglist) + (sizeof(TEE_PAGEINFO) * (tmp_sglist->infoLength))))
        return HM_ERROR;

    return HM_OK;
}

int32_t dynion_driver_syscall(int32_t swi_id, struct drv_param *params, uint64_t ull_permissions)
{
#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_MT6765)
    int32_t uw_ret;
#endif

    if (params == NULL || params->args == 0) {
        uart_printf_func("regs is invalid\n");
        return HM_ERROR;
    }
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_MT6765)
        SYSCALL_PERMISSION(SW_SYSCALL_SET_DYNMEM_CONFIG, ull_permissions,
                           DYNAMIC_ION_PERMISSION)
        uint64_t tmp_addr2 = args[0];
        ACCESS_CHECK_A64(args[0], sizeof(struct sglist));
        if (args[0] == 0 || check_sglist((struct sglist *)(uintptr_t)args[0]) != HM_OK) {
            args[0] = OS_ERROR;
            goto out;
        }
        ACCESS_CHECK_A64(tmp_addr2, ((struct sglist *)(uintptr_t)args[0])->sglistSize);
        ACCESS_READ_RIGHT_CHECK(tmp_addr2, ((struct sglist *)(uintptr_t)tmp_addr2)->sglistSize);
        uw_ret = set_dynmem_config((struct sglist *)(uintptr_t)tmp_addr2, (int)args[1]);
        args[0] = (uint64_t)uw_ret;
        SYSCALL_END;
#endif
    default:
        return HM_ERROR;
    }

    return HM_OK;
}

DECLARE_TC_DRV(
    dynion_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    dynion_driver_syscall,
    NULL,
    NULL
);
