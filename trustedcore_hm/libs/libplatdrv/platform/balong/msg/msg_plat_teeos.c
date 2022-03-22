/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */

#include "msg_plat.h"
#define MSG_MEM_ALIGN_DEFAULT 4
struct msg_mpool {
    u8 *base_va;
    phy_addr_t base_pa;
    u32 size;
    u32 offset;
};

static int g_msg_plat_inited = 0;
static struct msg_mpool g_msg_dmamem_pool;

int msg_plat_init(void)
{
    phy_addr_t phy_addr = 0;
    unsigned phy_size = 0;
    struct msg_mpool *mpool = NULL;

    mpool = &g_msg_dmamem_pool;

    mpool->base_va = (u8 *)bsp_mem_share_get("seshm_secos_msgdma", &phy_addr, &phy_size, SHM_SEC);
    if (mpool->base_va == NULL) {
        return -1;
    }
    mpool->base_pa = phy_addr;
    mpool->size = phy_size;
    mpool->offset = 0;

    g_msg_plat_inited = 1;
    return 0;
}

void *msg_dma_alloc(u32 size, unsigned long *pa, u32 align)
{
    unsigned long flags;
    void *mem_addr = NULL;
    phy_addr_t cur_pa, align_addr, align_sz;
    struct msg_mpool *mpool = &g_msg_dmamem_pool;

    if (!g_msg_plat_inited) {
        return mem_addr;
    }
    if (align < MSG_MEM_ALIGN_DEFAULT) {
        align = MSG_MEM_ALIGN_DEFAULT;
    }
    align_sz = msg_roundup(size, align);

    local_irq_save(flags);
    cur_pa = mpool->base_pa + mpool->offset;
    align_addr = msg_roundup(cur_pa, align);
    if (align_addr + align_sz > mpool->base_pa + mpool->size) {
        local_irq_restore(flags);
        msg_err("pushmem alloc failed,totalsz = 0x%x cur = 0x%x req = 0x%x\n", mpool->size, mpool->offset, size);
        return NULL;
    }
    mpool->offset = (align_addr - mpool->base_pa) + align_sz;
    mem_addr = (void *)(mpool->base_va + (align_addr - mpool->base_pa));
    *pa = align_addr;

    local_irq_restore(flags);

    return mem_addr;
}

/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(msg_driver, 0, 0, 0, TC_DRV_MODULE_INIT, bsp_msg_init, NULL, NULL, NULL, NULL);
/*lint -e528 +esym(528,*)*/
