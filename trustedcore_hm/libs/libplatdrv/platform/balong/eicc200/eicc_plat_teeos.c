/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#include "eicc_platform.h"
#include "eicc_dts.h"

#include "eicc_device.h"
#include "eicc_driver.h"
#include "eicc_core.h"
#include "eicc_pmsr.h" /* suspend/resume */
#include "eicc_proxy.h"

#define EICC_MEM_ALIGN_DEFAULT 4

struct eicc_mpool {
    u8 *base_va;
    eiccsoc_ptr_t base_pa;
    u32 size;
    u32 offset;
};

static u32 g_eicc_plat_inited = 0;
static osl_spinlock_t g_eicc_memlock;
static struct eicc_mpool g_eicc_pushmem_pool;

int eicc_plat_init(void)
{
    phy_addr_t phy_addr = 0;
    unsigned phy_size = 0;
    struct eicc_mpool *mpool = NULL;
    struct eicc_srv_meminfo meminfo;

    if (g_eicc_plat_inited) {
        return -1;
    }
    if (osl_spin_lock_init(&g_eicc_memlock)) {
        return -1;
    }
    if (eicc_reserved_meminfo(&meminfo)) {
        return -1;
    }
    if (meminfo.pushmem_rsv_sz == 0) {
        return -1;
    }
    mpool = &g_eicc_pushmem_pool;

    mpool->base_va = (u8 *)bsp_mem_share_get("seshm_secos_eiccptr", &phy_addr, &phy_size, SHM_SEC);
    if (mpool->base_va == NULL || phy_size < meminfo.pushmem_rsv_sz) {
        return -1;
    }
    mpool->base_pa = phy_addr;
    mpool->size = phy_size;
    mpool->offset = 0;

    g_eicc_plat_inited = 1;
    return 0;
}

void *eicc_pushmem_alloc(u32 size, eiccsoc_ptr_t *pa, u32 align)
{
    unsigned long flags;
    void *mem_addr = NULL;
    eiccsoc_ptr_t cur_pa, align_addr, align_sz;
    struct eicc_mpool *mpool = &g_eicc_pushmem_pool;

    if (!g_eicc_plat_inited) {
        return mem_addr;
    }
    if (align < EICC_MEM_ALIGN_DEFAULT) {
        align = EICC_MEM_ALIGN_DEFAULT;
    }
    align_sz = eicc_roundup(size, align);

    osl_spin_lock_irqsave(&g_eicc_memlock, flags);
    cur_pa = mpool->base_pa + mpool->offset;
    align_addr = eicc_roundup(cur_pa, align);
    if (align_addr + align_sz > mpool->base_pa + mpool->size) {
        osl_spin_unlock_irqrestore(&g_eicc_memlock, flags);
        eicc_print_crit("pushmem alloc failed,totalsz = 0x%x cur = 0x%x req = 0x%x\n", mpool->size, mpool->offset,
                        size);
        return NULL;
    }
    mpool->offset = (align_addr - mpool->base_pa) + align_sz;
    mem_addr = (void *)(mpool->base_va + (align_addr - mpool->base_pa));
    *pa = align_addr;

    osl_spin_unlock_irqrestore(&g_eicc_memlock, flags);

    return mem_addr;
}

/*******************************************************************************
 * 低功耗相关处理
 *******************************************************************************/
int bsp_eicc_suspend(void)
{
    int ret;
    ret = eicc_chn_suspend();
    if (ret) {
        return ret;
    }
    ret = eicc_dev_suspend();
    if (ret) {
        eicc_chn_resume();
        return ret;
    }
    return ret;
}

int bsp_eicc_resume(void)
{
    eicc_dev_resume();
    eicc_chn_resume();
    return 0;
}

int eicc_pmsr_init(void)
{
    return 0;
}

int eicc_rst_init(void)
{
    return 0;
}

int eicc_ca_handler(unsigned int arg1, void *arg2 __attribute__((unused)), unsigned int arg3 __attribute__((unused)))
{
    int ret = 0;
    eicc_print_error("in eicc_ca_handler, arg1 is : 0x%x\n", arg1);
    switch (arg1) {
        case EICC_BEFORE_RESET_CMD:
            ret = eicc_reset_proxy_shadow_ipipe_close();
            if (ret) {
                eicc_print_error("before reset eicc proxy config fail\n");
                return ret;
            }
            /* config teeos to modem eicc channel */
            break;

        case EICC_AFTER_RESET_CMD:
            ret = eicc_reset_proxy_shadow_ipipe_open();
            if (ret) {
                eicc_print_error("after reset eicc proxy config fail\n");
                return ret;
            }
            /* config teeos to modem eicc channel */

            break;

        default:
            eicc_print_error("unknown request\n");
            ret = -1;
    }
    return ret;
}

/*******************************************************************************
 * EICC 初始化相关处理
 *******************************************************************************/
int bsp_eicc_init(void)
{
    int ret;
    /* 某些平台低功耗恢复 会重新调用init，我们这里得有拦截 */
    static int inited = 0;
    if (inited) {
        return 0;
    }
    if (!eicc_init_meet()) {
        eicc_print_always("eicc init skiped\n");
        return 0;
    }

    ret = eicc_plat_init();
    if (ret) {
        eicc_print_error("eicc_plat_init failed\n");
        return -1;
    }

    ret = eicc_rst_init();
    if (ret) {
        eicc_print_error("eicc_rst_init failed\n");
        return -1;
    }

    ret = eicc_pmsr_init();
    if (ret) {
        eicc_print_error("eicc_pmsr_init failed\n");
        return -1;
    }

    ret = eicc_devices_init();
    if (ret) {
        eicc_print_error("eicc_devices_init failed\n");
        return -1;
    }
    ret = eicc_irqs_init();
    if (ret) {
        eicc_print_error("eicc_irqs_init failed\n");
        return -1;
    }

    ret = eicc_proxy_init();
    if (ret) {
        eicc_print_error("eicc_proxy_init failed\n");
        return -1;
    }
    eicc_print_error("before FUNC_MDRV_EICC_CAOPTS register\n");
    ret = bsp_modem_call_register(FUNC_MDRV_EICC_CAOPTS, eicc_ca_handler);
    if (0 != ret) {
        eicc_print_error("FUNC_MDRV_EICC_CAOPTS register fail\n");
        return -1;
    }
    inited = 1;
    eicc_print_always("eicc init ok\n");
    return ret;
}

/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(eicc_driver, 0, 0, 0, TC_DRV_MODULE_INIT, bsp_eicc_init, NULL, NULL, bsp_eicc_suspend, bsp_eicc_resume);
/*lint -e528 +esym(528,*)*/
