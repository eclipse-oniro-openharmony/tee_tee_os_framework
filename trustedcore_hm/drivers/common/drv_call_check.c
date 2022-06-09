/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Define the itrustee driver call check function
 * Create: 2020-02
 */
#include "drv_call_check.h"
#include <sre_audit_drv.h>
#include <mem_ops_ext.h>
#include <securec.h>
#include <tee_log.h>
#include <securec.h>
#include <sys/mman.h>
#include "mem_drv_map.h"
#include "drv_pal.h"
#include "hmdrv_stub_timer.h"

int32_t audit_check_fail(void)
{
#ifdef SRE_AUDIT
    uint32_t task_handle;
    if (task_caller(&task_handle) != 0) {
        tloge("get ta pid failed!\n");
        return DRV_CALL_ERROR;
    }
    kill_audit_task(task_handle, get_teesmc_hdlr());
    return DRV_CALL_OK;
#else
    return DRV_CALL_OK;
#endif
}

int32_t check_call_permission(uint64_t current_permission, uint64_t permission)
{
    if ((permission & current_permission) != permission) {
        audit_check_fail();
        return DRV_CALL_ERROR;
    }

    return DRV_CALL_OK;
}

static int32_t mmap_address_a32(struct call_params *param, uint32_t index,
                                uint32_t *temp_addr, int32_t *prot)
{
    int32_t ret;

    uint32_t addr = param->mmaped_ptrs[index].addr.addr_32;
    uint32_t size = param->mmaped_ptrs[index].len;
    if (addr == 0 || size == 0)
        return DRV_CALL_OK;

    ret = drv_map_from_task_under_tbac((uint32_t)param->pid, addr, size,
                                       (uint32_t)param->self_pid, temp_addr,
                                       prot, param->job_handler);
    if (ret != 0) {
        audit_check_fail();
        tloge("drv_map_from_task_under_tbac failed\n");
        return DRV_CALL_ERROR;
    }
    param->mmaped_ptrs[index].pptr = (void *)(&(addr));

    return DRV_CALL_OK;
}

static int32_t mmap_address_a64(struct call_params *param, uint32_t index,
                                uint64_t *temp_addr, int32_t *prot)
{
    int32_t ret;

    uint64_t addr = param->mmaped_ptrs[index].addr.addr_64;
    uint32_t size = param->mmaped_ptrs[index].len;
    if (addr == 0 || size == 0)
        return DRV_CALL_OK;

    ret = drv_map_from_task_under_tbac_handle((uint32_t)param->pid, addr, size,
                                              (uint32_t)param->self_pid, temp_addr,
                                              prot, param->job_handler);
    if (ret != 0) {
        audit_check_fail();
        tloge("drv_map_from_task_under_tbac failed\n");
        return DRV_CALL_ERROR;
    }
    param->mmaped_ptrs[index].pptr = (void *)(&(addr));

    return DRV_CALL_OK;
}

static int32_t copy_driver_data(struct call_params *param, uint32_t index)
{
    uint32_t size = param->mmaped_ptrs[index].len;

    if (!param->mmaped_ptrs[index].l_ptr) {
        param->mmaped_ptrs[index].l_ptr = (void *)malloc(size);
        if (param->mmaped_ptrs[index].l_ptr == NULL) {
            tloge("cmd %x: malloc size 0x%lx) failed\n", param->swi_id, size);
            unmap_maped_ptrs(param);
            return DRV_CALL_ERROR;
        }
        if (param->addr_type == A64)
            param->mmaped_ptrs[index].addr.addr_64 = (uint64_t)(uintptr_t)param->mmaped_ptrs[index].l_ptr;
        else
            param->mmaped_ptrs[index].addr.addr_32 = (uint32_t)(uintptr_t)param->mmaped_ptrs[index].l_ptr;

        errno_t ret_s = memcpy_s(param->mmaped_ptrs[index].l_ptr, size,
                                 (void *)(uintptr_t)(param->mmaped_ptrs[index].ptr), size);
        if (ret_s != EOK) {
            tloge("Failed to memcpy mmap_addr to l_ptr\n");
            unmap_maped_ptrs(param);
            return DRV_CALL_ERROR;
        }
    }
    return DRV_CALL_OK;
}

int32_t mmap_call_param(struct call_params *param, uint32_t index)
{
    int32_t prot = 0;
    uint64_t temp_addr = 0;
    int32_t ret;

    if (param == NULL || index >= MMAP_PTR_MAX) {
        tloge("mmap addr failed\n");
        return DRV_CALL_ERROR;
    }

    if (param->addr_type == A64)
        ret = mmap_address_a64(param, index, (uint64_t *)&temp_addr, &prot);
    else
        ret = mmap_address_a32(param, index, (uint32_t *)&temp_addr, &prot);
    if (ret != DRV_CALL_OK) {
        tloge("mmap addr failed\n");
        return DRV_CALL_ERROR;
    }

    param->mmaped_ptrs[index].pptr  = (void *)(&(param->mmaped_ptrs[index].addr));
    param->mmaped_ptrs[index].ptr  = (void *)(uintptr_t)(temp_addr);
    param->mmaped_ptrs[index].prot = prot;

    if (temp_addr == 0)
        return DRV_CALL_OK;

    if (((uint32_t)prot & PROT_EXEC) == PROT_EXEC) {
        tloge("ERROR: the param passed points to code area\n");
        unmap_maped_ptrs(param);
        return DRV_CALL_ERROR;
    }

    ret = copy_driver_data(param, index);
    if (ret != DRV_CALL_OK) {
        tloge("copy driver data failed\n");
        return DRV_CALL_ERROR;
    }
    return DRV_CALL_OK;
}

static int32_t addr_access_check(struct call_params *param)
{
    int32_t ret;
    uint32_t i;

    if (param == NULL) {
        tloge("invalid parameters, please check\n");
        return DRV_CALL_ERROR;
    }

    if (param->mmaped_ptr_cnt > MMAP_PTR_MAX - 1) {
        tloge("mmaped ptr count is wrong\n");
        return DRV_CALL_ERROR;
    }

    for (i = 0; i < param->mmaped_ptr_cnt; i++) {
        ret = mmap_call_param(param, i);
        if (ret != DRV_CALL_OK) {
            tloge("Failed to execute check_addr64_access\n");
            unmap_maped_ptrs(param);
            return DRV_CALL_ERROR;
        }
    }

    return DRV_CALL_OK;
}

static int32_t check_addr_write_right(const struct call_params *param)
{
    if (param == NULL) {
        tloge("invalid param, please check\n");
        return DRV_CALL_ERROR;
    }

    if (param->mmaped_ptr_cnt == 0)
        return DRV_CALL_OK;

    for (uint32_t i = 0; i < param->mmaped_ptr_cnt; i++) {
        if (param->mmaped_ptrs[i].access_flag != ACCESS_WRITE_RIGHT ||
            param->mmaped_ptrs[i].ptr == NULL)
            continue;

        if (((uint32_t)param->mmaped_ptrs[i].prot & PROT_WRITE) != PROT_WRITE) {
            tloge("swi_id %x, param %u, do not have write permission\n", param->swi_id, i);
            audit_check_fail();
            return DRV_CALL_OK;
        }

        if ((uint32_t)param->mmaped_ptrs[i].len == 0) {
            tloge("invalid addr len\n");
            return DRV_CALL_ERROR;
        }
    }

    return DRV_CALL_OK;
}

int32_t check_addr_access_right(struct call_params *param)
{
    int32_t ret;

    if (param == NULL) {
        tloge("invalid parameters, please check\n");
        return DRV_CALL_ERROR;
    }

    ret = addr_access_check(param);
    if (ret != DRV_CALL_OK) {
        tloge("cmd %x: ACCESS_CHECK failed: %d\n", param->swi_id, ret);
        return DRV_CALL_ERROR;
    }

    ret = check_addr_write_right(param);
    if (ret != DRV_CALL_OK) {
        tloge("cmd %x:access write right check failed\n", param->swi_id);
        unmap_maped_ptrs(param);
        return DRV_CALL_ERROR;
    }

    return DRV_CALL_OK;
}

void unmap_maped_ptrs(struct call_params *param)
{
    if (param == NULL) {
        tloge("invalid parameters, please check\n");
        return;
    }

    for (uint32_t i = 0; i < param->mmaped_ptr_cnt; i++) {
        errno_t ret_s;
        if ((uintptr_t)param->mmaped_ptrs[i].ptr && param->mmaped_ptrs[i].l_ptr &&
            ((uint32_t)param->mmaped_ptrs[i].prot & PROT_WRITE)) {
            ret_s = memcpy_s(param->mmaped_ptrs[i].ptr, param->mmaped_ptrs[i].len,
                             param->mmaped_ptrs[i].l_ptr, param->mmaped_ptrs[i].len);
            if (ret_s != EOK)
                tloge("memcpy_s failed, please check\n");
        }

        if (param->mmaped_ptrs[i].l_ptr) {
            ret_s = memset_s(param->mmaped_ptrs[i].l_ptr, param->mmaped_ptrs[i].len, 0, param->mmaped_ptrs[i].len);
            if (ret_s != EOK)
                tloge("memset_s failed, please check\n");
            free(param->mmaped_ptrs[i].l_ptr);
            param->mmaped_ptrs[i].l_ptr = NULL;
        }
        if (param->mmaped_ptrs[i].ptr)
            task_unmap((uint32_t)param->self_pid,
                (uintptr_t)param->mmaped_ptrs[i].ptr,
                (uint32_t)param->mmaped_ptrs[i].len);
    }
}
