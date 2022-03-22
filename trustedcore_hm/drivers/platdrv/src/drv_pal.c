/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: define the itrustee driver call function
 * Create: 2020-02
 */
#include "drv_pal.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/hmapi_ext.h>
#include <sys/usrsyscall_new_ext.h>
#include <hm_mman_ext.h>
#include <hm_unistd.h>
#include <mem_ops.h>
#include <mem_ops_ext.h>
#include <drv_mem.h>
#include <sre_hwi.h>
#include <mem_page_ops.h>
#include <tee_defines.h>
#include <tee_log.h>
#include <hmlog.h>
#include "platdrv.h"
#include "boot_sharedmem.h"
#include "drv_mem.h"
#include "drv_thread.h"
#include "drv_legacy_def.h"
#include "drv_task_map.h"

pid_t g_caller_pid = INVALID_CALLER_PID;

int32_t check_secureos_addr(paddr_t phy_addr __attribute__((unused)), uint32_t size __attribute__((unused)))
{
    /* Keep this function for thirdparty driver comatibilty */
    return 0;
}

int32_t phy_addr_check(paddr_t phy_addr __attribute__((unused)), uint32_t size __attribute__((unused)))
{
    /* Keep this function for thirdparty driver comatibilty */
    return 0;
}

void fake_gic_spi_notify(void)
{
    /*
     * We are already in tee mode, so no need to call gic_spi_notify() to get cpu.
     * This func is only for compatible with the source code of legacy driver
     */
    tlogv("FAKE GIC SPI NOTIFY\n");
}

/*
 * The meaning of this API has changed.
 * It is used to get pid of caller,
 * which is set in platdrv_handle_message()
 */
pid_t get_g_caller_pid(void)
{
    return g_caller_pid;
}

void set_g_caller_pid(pid_t caller_pid)
{
    g_caller_pid = caller_pid;
}

uint32_t task_caller(uint32_t *caller_pid)
{
    tid_t tid;
    int32_t pid_call = INVALID_CALLER_PID;

    if (caller_pid == NULL)
        return -EINVAL;

    int32_t ret = hm_gettid(&tid);
    if (ret != 0) {
        hm_error("failed to get tid\n");
        return -ESRCH;
    }

    /* for invalid pid, return "No such process" */
    ret = get_callerpid_by_tid(tid, (pid_t *)&pid_call);
    if (ret != 0)
        return -ESRCH;

    *caller_pid = pid_call;

    return 0;
}

int32_t sre_mmap(paddr_t base_addr, uint32_t size, uintptr_t *vm_addr,
                 secure_mode_type secure_mode, cache_mode_type cache_mode)
{
    int32_t drv_pid = hm_getpid();
    uint64_t temp_addr = 0;
    struct mem_type mode_type;

    if (vm_addr == NULL) {
        tloge("bad parameters!\n");
        return -1;
    }
    if (drv_pid < 0) {
        tloge("get drv pid failed!\n");
        return -1;
    }

    mode_type.secure_mode = secure_mode;
    mode_type.cache_mode = cache_mode;
    if (task_map_phy_mem_type(drv_pid, base_addr, size, &temp_addr, &mode_type) != 0) {
        tloge("task map error\n");
        return -1;
    }

#ifdef __aarch64__
    *vm_addr = temp_addr;
#else
    *vm_addr = (uint32_t)temp_addr & 0xFFFFFFFFUL;
#endif

    return 0;
}

void v7_dma_map_area(uintptr_t start, uint32_t size, int32_t dir)
{
    /* Keep this function for thirdparty driver comatibilty */
    __dma_map_area(start, size, dir);
}

void v7_dma_unmap_area(uintptr_t start, uint32_t size, int32_t dir)
{
    /* Keep this function for thirdparty driver comatibilty */
    __dma_unmap_area(start, size, dir);
}

int sre_unmap(uintptr_t virt_addr, uint32_t size)
{
    /* Keep this function for thirdparty driver comatibilty */
    return hm_munmap((void *)(uintptr_t)virt_addr, size);
}


/*
 * Keep this function for thirdparty driver comatibilty
 * This function is called by thirdparty module,
 * so we cannot change the parameters.
 */
int32_t sre_mmap_scatter(TEE_PAGEINFO *page_info, uint32_t page_info_num, uint32_t *vm_addr, uint32_t size,
                         secure_mode_type secure_mode, cache_mode_type cache_mode, user_mode_type user_mode)
{
    uint64_t temp_addr;
    struct drv_mem_mode mode_type;

    if (vm_addr == NULL) {
        tloge("vm_addr invalid\n");
        return -1;
    }

    mode_type.secure_mode = secure_mode;
    mode_type.cache_mode = cache_mode;
    mode_type.user_mode = user_mode;

    if (sre_mmap_scatter_handle(page_info, page_info_num, &temp_addr, size, &mode_type) != 0) {
        tloge("mmap scatter failed\n");
        return -1;
    }

    *vm_addr = (uint32_t)temp_addr & 0xFFFFFFFFUL;
    return 0;
}

int32_t sre_mmap_scatter_handle(TEE_PAGEINFO *page_info, uint32_t page_info_num, uint64_t *vm_addr, uint32_t size,
                                const struct drv_mem_mode *mode_type)
{
    uint32_t prot   = PROT_READ | PROT_WRITE;
    uint32_t pindex = 0;
    uint32_t all_pages = 0;
    int32_t ret;
    uint64_t mapped_addr = 0;
    uint32_t ta_pid;
    struct page_info_buffer page_info_buf = { (struct page_info *)page_info, (uint32_t)page_info_num };

    if (page_info == NULL || vm_addr == NULL || mode_type == NULL) {
        tloge("Invalid parameters!\n");
        return -1;
    }

    /* the memory size must equal to all phy size */
    while (pindex < page_info_num) {
        all_pages += page_info[pindex].npages;
        pindex++;
    }

    if ((all_pages << PAGE_SHIFT) != size) {
        tloge("the memory size must be equal to the physical size\n");
        return -1;
    }

    if (mode_type->secure_mode == non_secure)
        prot |= PROT_NS;
    if (mode_type->cache_mode == non_cache)
        prot |= PROT_MA_NC;

    if (mode_type->user_mode != USED_BY_USR) {
        ta_pid = INVALID_CALLER_PID;
    } else {
        if (task_caller(&ta_pid) != 0) {
            tloge("get pid failed!\n");
            return -1;
        }

        if ((int32_t)ta_pid < 0) {
            tloge("ta_pid is error");
            return -1;
        }
    }

    ret = hm_mmap_scatter_phy_mem(ta_pid, &mapped_addr, size, (int)prot, &page_info_buf);
    if (ret != 0 || mapped_addr == 0) {
        tloge("map scatter physical failed! ret : %d\n", ret);
        return -1;
    }

    *vm_addr = mapped_addr;

    return ret;
}

int32_t sre_munmap_scatter(uint32_t virt_addr, uint32_t size, user_mode_type user_mode)
{
    return sre_munmap_scatter_handle(virt_addr, size, user_mode);
}

int32_t sre_munmap_scatter_handle(uint64_t virt_addr, uint32_t size, user_mode_type user_mode)
{
    uint32_t ta_pid;
    int32_t ret;
    uint32_t tmp_size;
    uint64_t tmp_vaddr;

    tmp_vaddr = PAGE_ALIGN_DOWN(virt_addr);
    tmp_size  = (uint32_t)(PAGE_ALIGN_UP(size + virt_addr) - tmp_vaddr);

    if (user_mode != USED_BY_USR) {
        ret = sre_unmap((uintptr_t)virt_addr, size);
        if (ret != 0)
            tloge("unmap failed! ret : %d\n", ret);
        return ret;
    }

    if (task_caller(&ta_pid) != 0) {
        tloge("get caller pid failed!\n");
        return -1;
    }

    ret = task_unmap(ta_pid, tmp_vaddr, tmp_size);
    if (ret != 0) {
        tloge("task unmap for ns page failed! ret: %d\n", ret);
        return -1;
    }

    return ret;
}

uint32_t SRE_TaskDelete(uint32_t task_id __attribute__((unused)))
{
    return -1;
}

int tee_mmu_check_access_rights(__attribute__((unused)) uint32_t flag, __attribute__((unused)) uint32_t va,
                                __attribute__((unused)) uint32_t size)
{
    /*
     * The prot is checked in drv_map_from_task() & ACCESS_CHECK(),
     * This func is reserved only to compatible with legecy driver code
     */
    return 0;
}

uint32_t HM_IntLock(void)
{
    irq_lock();
    return 0;
}

void HM_IntRestore(void)
{
    irq_unlock();
}

int32_t drv_map_paddr_to_task(paddr_t phy_addr, uint32_t size, uint32_t *virt_addr,
                              uint32_t secure_mode, uint32_t cache_mode)
{
    uint64_t temp_addr;
    if (virt_addr == NULL) {
        tloge("virt_addr invalid\n");
        return -1;
    }

    if (drv_map_paddr_to_task_handle(phy_addr, size, &temp_addr, secure_mode, cache_mode) != 0) {
        tloge("map addr failed\n");
        return -1;
    }

    *virt_addr = (uint32_t)temp_addr & 0xFFFFFFFFUL;

    return 0;
}

int32_t drv_map_paddr_to_task_handle(paddr_t phy_addr, uint32_t size, uint64_t *virt_addr,
                                     uint32_t secure_mode, uint32_t cache_mode)
{
    int32_t drv_pid;
    uint32_t result;
    uint32_t ta_pid;
    struct mem_type mode_type;
    int32_t ret;

    if (virt_addr == NULL) {
        tloge("invalid params! virt_addr is NULL\n");
        return -1;
    }

    drv_pid = hm_getpid();
    if (drv_pid < 0) {
        tloge("get drv pid failed!\n");
        return -1;
    }

    result = task_caller(&ta_pid);
    if (result != 0) {
        tloge("get ta pid failed!\n");
        return -1;
    }

    mode_type.secure_mode = secure_mode;
    mode_type.cache_mode = cache_mode;

    ret = task_map_phy_mem_type(ta_pid, phy_addr, size, virt_addr, &mode_type);
    if (ret != 0) {
        tloge("task map error\n");
        return -1;
    }

    return 0;
}

int32_t drv_unmap_from_task(uint32_t virt_addr, uint32_t size)
{
    return drv_unmap_from_task_handle(virt_addr, size);
}

int32_t drv_unmap_from_task_handle(uint64_t virt_addr, uint32_t size)
{
    uint32_t ret;
    uint32_t ta_pid;

    ret = task_caller(&ta_pid);
    if (ret != 0) {
        tloge("get ta pid failed!\n");
        return -1;
    }

    if (task_unmap(ta_pid, virt_addr, size) != 0) {
        tloge("unmap from task failed!\n");
        return DRV_CALL_ERROR;
    }
    return DRV_CALL_OK;
}
