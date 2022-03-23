/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: dynion driver func
 * Author: Heyanhong heyanhong2@huawei.com
 * Create: 2020-09-14
 */
#include "dynion.h"      /* struct sglist */
#include <drv_module.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include "product_config.h"
#include "dynion_config.h"
#include "hmdrv_stub.h" /* keep this last */

int32_t get_dynmem_addr(struct sglist *sglist, int32_t type, uint64_t *paddr, uint32_t *psize)
{
    if (sglist == NULL) {
        tloge("sglist is NULL\n");
        return -1;
    }

    if (paddr == NULL || psize == NULL) {
        tloge("paddr or psize is NULL\n");
        return -1;
    }

    enum DDR_SEC_REGION feature = ((uint32_t)type >> SEC_FEATURE_OFFSET);
    if (feature != DDR_SEC_EID) {
        tloge("feature type:%d is not suuport\n", feature);
        return -1;
    }

    if (sglist->infoLength != 1) { /* EID is continues phy region, only one index */
        tloge("infoLength:%u not match\n", sglist->infoLength);
        return -1;
    }

    TEE_PAGEINFO *page_info = (TEE_PAGEINFO *)(sglist->info);
    if (page_info->npages > MAX_PAGE_NUM) {
        tloge("npages:%u invalid\n", page_info->npages);
        return -1;
    }

    uint64_t start_addr = page_info->phys_addr;
    uint32_t size = page_info->npages * PAGE_SIZE;
    if (start_addr + size < start_addr) {
        tloge("phy addr and size invalid\n");
        return -1;
    }

    *paddr = start_addr;
    *psize = size;
    return 0;
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
    int32_t uw_ret;

    if (params == NULL || params->args == 0) {
        uart_printf_func("regs is invalid\n");
        return HM_ERROR;
    }
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_SET_DYNMEM_CONFIG, ull_permissions, DYNAMIC_ION_PERMISSION)
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
