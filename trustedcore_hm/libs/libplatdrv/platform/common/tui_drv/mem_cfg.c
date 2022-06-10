/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secure memory interface for tui driver
 * Author: DuJie dujie7@huawei.com
 * Create: 2020-03-05
 */
#include "mem_cfg.h"

#include <drv_cache_flush.h>
#include <drv_mem.h>
#include <drv_pal.h>
#include <drv_task_map.h>
#ifndef TEE_SUPPORT_TUI_MTK_DRIVER
#include <sec_region_ops.h>
#include <hisi_disp.h>
#endif
#include <libhwsecurec/securec.h>
#include <mem_mode.h>
#include <mem_ops.h>
#include <mem_ops_ext.h>
#include <boot_sharedmem.h>
#include <tee_log.h>
#ifdef TEE_SUPPORT_M_DRIVER
#include <secmem.h>
#include <secmem_core_api.h>
#endif
#include "drv_cache_flush.h"

#include "tui_drv.h"
/* global task no enough memory to map framebuffer memory, so step by 2M */
#define STEP_SIZE (2 * 1024 * 1024)

static void clear_mem_content(const struct mem_cfg *cfg)
{
    uint64_t start_phy;
    uint32_t step_size;
    uint32_t vm_addr;

    start_phy = cfg->phy_addr;

    while (start_phy < (cfg->phy_addr + cfg->size)) {
        uint32_t left_size = (cfg->phy_addr + cfg->size - start_phy);
        step_size          = ((left_size > STEP_SIZE) ? STEP_SIZE : left_size);

        if (step_size == 0)
            break;

        if (sre_mmap(start_phy, step_size, &vm_addr, secure, cache) != 0) {
            tloge("map framebuffer error\n");
            return;
        }

        errno_t rc = memset_s((void *)(uintptr_t)vm_addr, step_size, 0, step_size);
        if (rc != EOK)
            tloge("memset_s error: ret=[0x%x]\n", rc);

        v7_dma_flush_range(vm_addr, vm_addr + step_size);

        if (sre_unmap(vm_addr, step_size) != 0)
            tloge("unmap mem failed\n");

        start_phy += step_size;
    }
}

#ifdef TEE_SUPPORT_M_DRIVER
static int32_t cfg_secmem(struct mem_cfg *cfg, int32_t mem_type)
{
    mem_cfg_para_s mem = { 0 };
    mem.input.para_addr.phy_addr = cfg->phy_addr;
    mem.input.para_addr.size = cfg->size;
    mem.mem_type = mem_type;
    mem.in_type = MEM_INPUT_ADDR;
    return secmem_sec_cfg(&mem, 0, 0);
}
#endif

bool unset_secure_mem(struct mem_cfg *cfg, int32_t mem_type)
{
    struct tui_sglist_page sglist_page;
    struct tui_ion_sglist_k *sgl = &sglist_page.sglist;

    if (cfg == NULL || cfg->info_length == 0)
        return false;

    tlogd("unset mem size 0x%x, mode 0x%x, caller 0x%x", cfg->size, cfg->mode, cfg->caller_pid);

    if (cfg->mode == SECURE_DISABLE)
        return true;

    sgl->info_length            = cfg->info_length;
    sgl->ion_size               = cfg->size;
    sgl->page_info[0].npages    = cfg->npages;
    sgl->page_info[0].phys_addr = cfg->phy_addr;
    sgl->sglist_size            = sizeof(struct tui_page_info_k) * cfg->info_length + sizeof(*sgl);

    if (cfg->need_clear)
        clear_mem_content(cfg);

    int32_t ret = task_unmap(cfg->caller_pid, cfg->vm_addr, cfg->size);
    if (ret != 0) {
        tloge("unmap fb cfg mem failed 0x%x", ret);
        return false;
    }
    cfg->vm_addr = 0;

    if (sgl->page_info[0].phys_addr == 0) {
        tloge("convert phys error\n");
        return false;
    }

    if (phy_addr_check(sgl->page_info[0].phys_addr, sgl->ion_size) != 0) {
        tloge("phy addr check error\n");
        return false;
    }

#ifdef TEE_SUPPORT_M_DRIVER
    /* add secmem_sec_cfg */
    ret = cfg_secmem(cfg, mem_type);
#else
    (void)mem_type;
    ret = ddr_sec_cfg((struct sglist *)sgl, (int32_t)DDR_SEC_TUI, (int32_t)DDR_UNSET_SEC);
#endif
    if (ret != 0) {
        tloge("config mem failed 0x%x\n", ret);
        return false;
    }
    cfg->mode = SECURE_DISABLE;

    return true;
}

#ifdef TEE_SUPPORT_M_DRIVER
static bool set_secure_mem_for_mtk(struct mem_cfg *cfg, int32_t mem_type, mem_cfg_para_s *mem)
{
    int32_t ret;

    mem->input.para_addr.phy_addr = cfg->phy_addr;
    mem->input.para_addr.size = cfg->size;
    mem->mem_type = mem_type;
    mem->in_type = MEM_INPUT_ADDR;

    ret = secmem_sec_cfg(mem, 0, 1);
    if (ret != 0) {
        tloge("skip config mem failed 0x%x\n", ret);
        return false;
    }

    ret = secmem_sec_check(mem, 0);
    if (ret != 1) { /* func is ret 1 is sec mem, 0 is unsec mem */
        tloge("skip config mem failed 0x%x\n", ret);
        (void)secmem_sec_cfg(mem, 0, 0);
        return false;
    }

    return true;
}
#endif

bool set_secure_mem(struct mem_cfg *cfg, int32_t mem_type)
{
    int32_t ret;
    struct tui_sglist_page sglist_page;
    struct tui_ion_sglist_k *sgl = &sglist_page.sglist;

    if (cfg == NULL || cfg->info_length == 0)
        return false;

    tlogd("begin set secure, size 0x%x,  mode 0x%x", cfg->size, cfg->mode);

    if (cfg->mode == SECURE_ENABLE)
        return true;

    sgl->info_length            = cfg->info_length;
    sgl->ion_size               = cfg->size;
    sgl->page_info[0].npages    = cfg->npages;
    sgl->page_info[0].phys_addr = cfg->phy_addr;
    sgl->sglist_size            = sizeof(struct tui_page_info_k) * cfg->info_length + sizeof(*sgl);

#ifdef TEE_SUPPORT_M_DRIVER
    mem_cfg_para_s mem = { 0 };
    if (!set_secure_mem_for_mtk(cfg, mem_type, &mem))
        return false;
#else
    (void)mem_type;
    (void)ddr_sec_cfg((struct sglist *)sgl, (int32_t)DDR_SEC_TUI, (int32_t)DDR_SET_SEC);
    ret = ddr_sec_cfg((struct sglist *)sgl, (int32_t)DDR_SEC_TUI, (int32_t)DDR_CHECK_SEC);
    if (ret != 0) {
        tloge("config mem failed 0x%x\n", ret);
        return false;
    }
#endif
    ret = drv_map_paddr_to_task(cfg->phy_addr, cfg->size, &cfg->vm_addr, secure, cache);
    if (ret != 0) {
        tloge("map failed 0x%x", ret);
#ifdef TEE_SUPPORT_M_DRIVER
        (void)secmem_sec_cfg(&mem, 0, 0);
#else
        (void)ddr_sec_cfg((struct sglist *)sgl, (int32_t)DDR_SEC_TUI, (int32_t)DDR_UNSET_SEC);
#endif
        return false;
    }

    if (task_caller(&cfg->caller_pid) != 0)
        tloge("get task caller failed");

    cfg->mode = SECURE_ENABLE;

    return true;
}

void init_mem_cfg(struct mem_cfg *mem_cfg, const struct tui_config *cfg, bool need_clear)
{
    if (mem_cfg == NULL || cfg == NULL)
        return;

    mem_cfg->phy_addr    = cfg->phy_addr;
    mem_cfg->size        = cfg->phy_size;
    mem_cfg->npages      = cfg->npages;
    mem_cfg->info_length = cfg->info_length;
    mem_cfg->need_clear  = need_clear;

    tlogd("init mem, set fb info len 0x%llx, size 0x%x", mem_cfg->info_length, mem_cfg->size);
}
