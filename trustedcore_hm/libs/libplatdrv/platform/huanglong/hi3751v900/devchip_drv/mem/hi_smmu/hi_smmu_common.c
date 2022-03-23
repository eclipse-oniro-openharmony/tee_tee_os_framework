/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: hi_smmu
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "hi_smmu_mem.h"
#include "hi_smmu_common.h"
#include "bitmap.h"
#include "hi_tee_drv_mem_layout.h"
#include "hi_sec_mmz.h"

#define SHIFT_4 4

struct mem_bitmap {
    unsigned long *bitmap;
    unsigned long bitmap_pfn_base;
    unsigned long bitmap_pfn_count;
};

struct mem_bitmap g_sec_mem_bitmap = {0};
struct mem_bitmap g_smmu_mem_bitmap = {0};

struct list_head g_smmu_list;
struct hi_tee_hal_mutex g_smmu_lock;

unsigned long long g_smmu_scb_ttbr_g;
unsigned long long g_smmu_e_waddr_g;
unsigned long long g_smmu_e_raddr_g;

/*
 * share mem start and size.
 */
static unsigned long long g_shrm_start;
static unsigned long long g_shrm_size;

/* random number < 0x4000, delay about 500us */
static void random_delay(void)
{
    unsigned int loop = 0xffffffff;

    if (hi_tee_drv_hal_rng_generate(&loop, sizeof(loop))) {
        hi_tee_drv_hal_sys_reset();
    }

    loop = loop & 0x3fff;
    while (loop--) {
        asm("nop");
    }
}

static int config_sec_mem_bitmap(void *pageinfoaddr, unsigned long long total_size, int config)
{
    struct hi_tz_pageinfo *pginfo = NULL;
    unsigned long bitmap_cnt, bitmap_start, tmp;
    unsigned int size;
    unsigned int map_size = 0;

    if (pageinfoaddr == NULL || total_size == 0) {
        pr_err("%s %d err args pageinfo:%p total_size:0x%x\n", __FUNCTION__, __LINE__, pageinfoaddr, total_size);
        goto out;
    }
    size = ALIGN((unsigned int)total_size, HISI_SMMU_BLOCK_SIZE);

    pginfo = (struct hi_tz_pageinfo *)pageinfoaddr;
    for (; map_size < size;) {
        if (pginfo == NULL) {
            goto out;
        }
        /* set in bitmap   */
        bitmap_start = ((pginfo->phys_addr) >> HISI_PAGE_SHIFT) - g_sec_mem_bitmap.bitmap_pfn_base;
        bitmap_cnt = pginfo->npages;
        tmp = (pginfo->phys_addr >> HISI_PAGE_SHIFT) + bitmap_cnt;
        if ((bitmap_start + bitmap_cnt) < bitmap_start ||
            ((pginfo->phys_addr >> HISI_PAGE_SHIFT) + bitmap_cnt) < (pginfo->phys_addr >> HISI_PAGE_SHIFT) ||
            (pginfo->phys_addr >> HISI_PAGE_SHIFT) < g_sec_mem_bitmap.bitmap_pfn_base ||
            (bitmap_cnt > g_sec_mem_bitmap.bitmap_pfn_count) ||
             tmp > (g_sec_mem_bitmap.bitmap_pfn_base + g_sec_mem_bitmap.bitmap_pfn_count)) {
            pr_err("%s:failed base:0x%lx,count:0x%lx, tmp:0x%lx, bitmap_no:0x%lx, bitmap_cnt:0x%lx phy:0x%llx\n",
                   __FUNCTION__, g_sec_mem_bitmap.bitmap_pfn_base, g_sec_mem_bitmap.bitmap_pfn_count,
                   tmp, bitmap_start, bitmap_cnt, pginfo->phys_addr);
            goto out;
        }

        if (config) {
            bitmap_set(g_sec_mem_bitmap.bitmap, bitmap_start, bitmap_cnt);
        } else {
            bitmap_clear(g_sec_mem_bitmap.bitmap, bitmap_start, bitmap_cnt);
        }

        map_size = map_size + (pginfo->npages << HISI_PAGE_SHIFT);
        pginfo++;
    }

    return HI_SUCCESS;

out:
    return HI_FAILED;
}


int clear_sec_mem_bitmap(void *pageinfoaddr, unsigned long long total_size)
{
    return config_sec_mem_bitmap(pageinfoaddr, total_size, 0);
}

int set_sec_mem_bitmap(void *pageinfoaddr, unsigned long long total_size)
{
    return config_sec_mem_bitmap(pageinfoaddr, total_size, 1);
}

int check_mem_secure_attr(unsigned long long pageinfo, unsigned long long total_size,
                          unsigned int nblocks, int *result)
{
    struct hi_tz_pageinfo *pginfo = NULL;
    struct hi_tz_pageinfo *virt = NULL;
    unsigned long bitmap_no, bitmap_start, bitmap_cnt, tmp;
    int found = 0;
    unsigned int map_size = 0;
    int ret = HI_FAILED;

    if (pageinfo == 0 || total_size == 0 || result == NULL) {
        pr_err("%s %d err args result:%p, total_size:%d \n", __FUNCTION__, __LINE__, result, total_size);
        return HI_FAILED;
    }

    /* normal mem, cache  */
    pginfo = (struct hi_tz_pageinfo *)hi_tee_drv_hal_remap(pageinfo, sizeof(struct hi_tz_pageinfo) * nblocks, false, 1);
    if (pginfo == NULL) {
        pr_err("%s %d remap failed!\n", __FUNCTION__, __LINE__);
        return HI_FAILED;
    }
    virt = pginfo;

    for (; map_size < ALIGN((unsigned int)total_size, HISI_SMMU_BLOCK_SIZE);) {
        if (pginfo == NULL) {
            pr_err("%s %d pginfo is overflow!\n", __FUNCTION__, __LINE__);
            goto exit;
        }

        bitmap_start = (pginfo->phys_addr >> HISI_PAGE_SHIFT) - g_sec_mem_bitmap.bitmap_pfn_base;
        bitmap_cnt = (unsigned long)pginfo->npages;
        tmp = (pginfo->phys_addr >> HISI_PAGE_SHIFT) + bitmap_cnt;
        if ((bitmap_start + bitmap_cnt) < bitmap_start ||
            ((pginfo->phys_addr >> HISI_PAGE_SHIFT) + bitmap_cnt) < (pginfo->phys_addr >> HISI_PAGE_SHIFT) ||
            (pginfo->phys_addr >> HISI_PAGE_SHIFT) < g_sec_mem_bitmap.bitmap_pfn_base ||
            (bitmap_cnt > g_sec_mem_bitmap.bitmap_pfn_count) ||
             tmp > (g_sec_mem_bitmap.bitmap_pfn_base + g_sec_mem_bitmap.bitmap_pfn_count)) {
            pr_err("failed phy:0x%llx base:0x%lx,count:0x%lx, bitmap_no:0x%lx, bitmap_cnt:0x%lx \n", pginfo->phys_addr,
                   g_sec_mem_bitmap.bitmap_pfn_base, g_sec_mem_bitmap.bitmap_pfn_count, bitmap_start, bitmap_cnt);
            goto exit;
        }

        /* check if there is any set bit in the mem range     */
        bitmap_no = bitmap_find_next_set_bit(g_sec_mem_bitmap.bitmap, bitmap_start + bitmap_cnt, bitmap_start);
        if (bitmap_no < (bitmap_start + bitmap_cnt)) {
            /* find set bit:secure mem found */
            found = 1;
            break;
        }
        map_size = map_size + (pginfo->npages << HISI_PAGE_SHIFT);
        pginfo++;
    }

    *result = (found) ? 1 : 0;
    ret = HI_SUCCESS;
exit:
    hi_tee_drv_hal_unmap((void *)virt, sizeof(struct hi_tz_pageinfo) * nblocks);
    return ret;
}

unsigned long get_shrm_size()
{
    return g_shrm_size;
}

int hi_smmu_suspend(void)
{
    return 0;
}

int hi_smmu_resume(void)
{
    return smmu_hardware_resume();
}

static inline void smmu_mutex_init(struct hi_tee_hal_mutex *lock)
{
    int ret;

    ret = hi_tee_drv_hal_mutex_init("smmu_lock", lock);
    if (ret) {
        pr_err("Create mutex failed(0x%x).\n", ret);
    }
}

static inline unsigned int smmu_read32(unsigned long long addr)
{
    return *(const volatile unsigned int*)hi_tee_drv_hal_phys_to_virt(addr);
}

static inline void smmu_write32(unsigned long long addr, unsigned int value)
{
    asm volatile("dsb");
    *(volatile unsigned int *)hi_tee_drv_hal_phys_to_virt(addr) = value;
    asm volatile("dsb");
}

int smmu_set_sec_flags(unsigned long long sec_smmu, unsigned long long size);

/* init PASTC reg */
static void smmu_reg_init(unsigned long long smmu_ptable_addr)
{
    /*
     * PASTC_BSE_REG is mapped in drivers/secure_mmu/
     * secure_page_table_plat.c when secure os is init.
     * And virt address is the same with PASTC_BSE_REG.
     * And map size is configged the real eara of PASTC reg.
     */
    unsigned int val = 0;
    /* when reset, SRAM should be clear.Here wait it finished,Just check one time after booting  */
    while (!val) {
        val = smmu_read32(PASTC_BSE_REG);
        val = val & 0x2;
    }

    /* 0x00:4k, 0x01:16k, 0x10:64k, 0x11:reserve */
#if defined(PAGESIZE_4K)
    val = 0x00;
#elif defined(PAGESIZE_16K)
    val = 0x01;
#elif defined(PAGESIZE_64K)
    val = 0x02;
#else
    val = 0x00;  // default
#endif
    smmu_write32(PASTC_BSE_REG + PASTC_PAGE_SIZE, val);
    /* enable interrupt */
    smmu_write32(PASTC_BSE_REG + PASTC_INT, 0x0);
    /* config pagetable base  address   */
    smmu_write32(PASTC_BSE_REG + PASTC_TTBR, smmu_ptable_addr & 0xffffffff);
    smmu_write32(PASTC_BSE_REG + PASTC_TTBR_H, (smmu_ptable_addr >> 32) & 0xf); // shift right 32 bit
    /* clear interrupt mask bit   */
    smmu_write32(PASTC_BSE_REG + PASTC_INT_MASK, 0);

    val = smmu_read32(REG_BASE_SYS_CTRL + REG_SC_GEN18);
    val = (val >> REG_EC_STATUS_SHIFT) & REG_EC_STATUS_MASK;
    if (val == REG_EC_STATUS) {
        /* GEN18[14-13] 2'b10 means the chipset is the ES which before EC
         * clear ddr data: 0:2 times  1:1 time
         */
        smmu_write32(PASTC_BSE_REG + PASTC_CLR_SET_NUM, 1);
    } else {
        /* for cs/ec chip, the meaning of bit[0] has been changed
         * its default value is 1 which means sram is in the state of initialization
         * it should be set to 0 at the end of pastc initialization
         */
        smmu_write32(PASTC_BSE_REG + PASTC_CLR_SET_NUM, 0);
    }

    return;
}

int smmu_hardware_resume(void)
{
    struct sec_mmb *m = NULL;
    struct sec_mmb *n = NULL;
    int ret = HI_SUCCESS;

    /* init PASTC  */
    smmu_reg_init(g_smmu_scb_ttbr_g);

    /* reinit PASTC sram */
    list_for_each_entry_safe(m, n, &g_smmu_list, list) {
        if (m->flag) {
        ret = smmu_set_sec_flags(m->sec_smmu, m->size);
        if (ret != HI_SUCCESS) {
            pr_err("resume failed!\n");
            break;
        }
    }
    }

    return ret;
}

static int smmu_common_init_s(unsigned long long smmu_e_raddr, unsigned long long smmu_pgtbl)
{
    if (smmu_e_raddr == 0 || smmu_pgtbl == 0) {
        pr_err("err args\n");
        return HI_FAILED;
    }

    g_smmu_e_raddr_g = ALIGN(smmu_e_raddr, SMMU_ERR_RW_SIZE);
    g_smmu_e_waddr_g = smmu_e_raddr + SMMU_ERR_RW_SIZE;
    g_smmu_scb_ttbr_g = smmu_pgtbl;

    /* init PASTC  */
    smmu_reg_init(smmu_pgtbl);

    INIT_LIST_HEAD(&g_smmu_list);
    smmu_mutex_init(&g_smmu_lock);

    g_shrm_start = (unsigned long long)hi_tee_drv_mem_get_zone_range(NON_SEC_OS_MEM, &g_shrm_size);
    if (!g_shrm_size) {
        pr_err("Get share mem range failed!\n");
        return HI_FAILED;
    } else {
        return HI_SUCCESS;
    }
}

void get_sec_smmu_pgtblbase(unsigned long long *smmu_e_raddr,
                            unsigned long long *smmu_e_waddr,
                            unsigned long long *smmu_pgtbl)
{
    *smmu_e_raddr = g_smmu_e_raddr_g;
    *smmu_e_waddr = g_smmu_e_waddr_g;
    *smmu_pgtbl = g_smmu_scb_ttbr_g;
}


/* interrupt handler */
static int smmu_interrupt_handler(void)
{
    unsigned int val;

    val = smmu_read32(PASTC_BSE_REG + PASTC_INT_STAT);
    if (!(val & (0x1 << 0))) {
        pr_err("start mode not finished!\n");
        /* clear interrupt flag  */
    } else {
        pr_err("start mode finished!\n");
        /* clear interrupt flag  */
        smmu_write32(PASTC_BSE_REG + PASTC_INT_CLR, 0x1);
    }

    if (val & (0x1 << 4)) { // shift left 4 bit
        pr_err("Read pgtable and Rresp error!\n");
        /* clear interrupt flag  */
        smmu_write32(PASTC_BSE_REG + PASTC_INT_CLR, 0x1 << 4); // shift left 4 bit
    }
    if (val & (0x1 << 5)) { // shift left 5 bit
        pr_err("Invalidate pagetable!\n");
        /* clear interrupt flag  */
        smmu_write32(PASTC_BSE_REG + PASTC_INT_CLR, 0x1 << 5); // shift left 5 bit
    }
    if (val & (0x1 << 6)) { // shift left 6 bit
        pr_err("Clear ddr and Bresp error!\n");
        /* clear interrupt flag  */
        smmu_write32(PASTC_BSE_REG + PASTC_INT_CLR, 0x1 << 6); // shift left 6 bit
    }
    if (val & (0x1 << 7)) { // shift left 7 bit
        pr_err("Rresp error!\n");
        /* clear interrupt flag  */
        smmu_write32(PASTC_BSE_REG + PASTC_INT_CLR, 0x1 << 7); // shift left 7 bit
    }
    if (val & (0x1 << 8)) { // shift left 8 bit
        pr_err("Check and not all 0!\n");
        /* clear interrupt flag  */
        smmu_write32(PASTC_BSE_REG + PASTC_INT_CLR, 0x1 << 8); // shift left 8 bit
    }
    return 0;
}

int dump_mem(void)
{
    struct sec_mmb *m = NULL, *n = NULL;
    int flag __MAYBE_UNUSED;

    pr_info("\nSEC MEM:\n");
    pr_info("---------------------------------------------------------------------------------------------------\n");
    list_for_each_entry_safe(m, n, &g_smmu_list, list) {
        if (drv_tee_mmz_is_sec(m->phys_addr))
            flag = 1;
        else {
            if (m->flag)
                flag = 1;
            else
                flag = 0;
        }

        pr_info("sec_smmu=0x%llx phys=0x%llx virt=0x%x nosec_smmu=0x%llx size=0x%llx tz_memblock=0x%llx  \
                pginfo=0x%llx %s  %s  %s\n",
            m->sec_smmu, m->phys_addr, (uintptr_t)m->sec_virt,
            m->nosec_smmu, m->size, m->tz_memblocks, m->meminfo_addr, flag ? "S" : "NS",
            m->memtype ? "SMMU" : "MMZ", m->name);
    }
    pr_info("---------------------------------------------------------------------------------------------------\n");

    return 0;
}

int insert_sec_mmb(struct sec_mmb *sec_mmb)
{
    struct sec_mmb *sec_mmb_n = NULL;
    struct sec_mmb *m = NULL, *n = NULL;
    unsigned long long handle_id = 1;

    if (sec_mmb == NULL) {
        pr_err("args should not be NULL.\n");
        return HI_FAILED;
    }

    if (sec_mmb->handle_id != 0) {
        /* already insert, just return  */
        return HI_SUCCESS;
    }

    if (list_empty(&g_smmu_list)) {
        sec_mmb->handle_id = 1;
        list_add(&(sec_mmb->list), &g_smmu_list);

        return HI_SUCCESS;
    }

    list_for_each_entry_safe(m, n, &g_smmu_list, list) {
        if (m->handle_id == handle_id) {
            handle_id++;
            continue;
        }
        if (m->handle_id > handle_id) {
            /* find unused handle_id   */
            sec_mmb_n = m;
            break;
        }
    }

    sec_mmb->handle_id = handle_id;
    if (sec_mmb_n == NULL) {
        /* insert to the end of list   */
        list_add_tail(&(sec_mmb->list), &g_smmu_list);
    } else {
        list_add_tail(&(sec_mmb->list), &(sec_mmb_n->list));
    }

    return HI_SUCCESS;
}

struct sec_mmb *get_sec_mmb_by_handle_id(unsigned long long handle_id)
{
    struct sec_mmb *sec_mmb = NULL;
    struct sec_mmb *m = NULL, *n = NULL;

    if (!handle_id) {
        pr_debug("handle_id should not be 0 \n");
        return NULL;
    }

    list_for_each_entry_safe(m, n, &g_smmu_list, list) {
        if (handle_id == (m->handle_id)) {
            sec_mmb = m;
            break;
        }
    }

    if (sec_mmb == NULL) {
        pr_err("inval handle_id, handle_id:0x%llx \n", handle_id);
        return NULL;
    }

    return sec_mmb;
}

struct sec_mmb *get_sec_mmb_by_secsmmu(unsigned long long sec_smmu)
{
    struct sec_mmb *sec_mmb = NULL;
    struct sec_mmb *m = NULL, *n = NULL;

    if (!sec_smmu) {
        pr_err("err args:sec_smmu:0x%llx\n", sec_smmu);
        return NULL;
    }

    list_for_each_entry_safe(m, n, &g_smmu_list, list) {
        /*
         * sometimes, the init value of m->sec_smmu is 0, and this case should be took into account
         * and this case should be avoid
         */
        if (!m->sec_smmu)
            continue;
        if ((sec_smmu < (m->sec_smmu + m->size)) && (sec_smmu >= m->sec_smmu)) {
            sec_mmb = m;
            break;
        }
    }

    if (sec_mmb == NULL) {
        /*
         * in some times, sec_mmb is NULL, and a new sec_mmb struct is
         * will alloc later.
         */
    }

    return sec_mmb;
}

struct sec_mmb *get_sec_mmb_by_phys(unsigned long long phys_addr)
{
    struct sec_mmb *sec_mmb = NULL;
    struct sec_mmb *m = NULL, *n = NULL;

    if (!phys_addr) {
        pr_err("err args:phys_addr:0x%llx\n", phys_addr);
        return INVIDE_ADDR;
    }

    list_for_each_entry_safe(m, n, &g_smmu_list, list) {
        /*
         * sometimes, the init value of m->phys_addr is 0, and this case should be took into account
         * and this case should be avoid
         */
        if (!m->phys_addr)
            continue;
        if ((phys_addr < (m->phys_addr + m->size)) &&
                    (phys_addr >= m->phys_addr)) {
            sec_mmb = m;
            break;
        }
    }

    if (sec_mmb == NULL) {
        /*
         * in some times, sec_mmb is NULL, and a new sec_mmb struct is
         * will alloc later.
         */
    }

    return sec_mmb;
}

struct sec_mmb *get_sec_mmb_by_secvirt(void *sec_virt)
{
    struct sec_mmb *sec_mmb = NULL;
    struct sec_mmb *m = NULL, *n = NULL;

    if (sec_virt == NULL) {
        pr_err("err args, sec_virt:0x%x\n", (uintptr_t)sec_virt);
        return INVIDE_ADDR;
    }

    list_for_each_entry_safe(m, n, &g_smmu_list, list) {
        /*
         * sometimes, the init value of m->sec_virt is 0, and this case should be took into account
         * and this case should be avoid
         */
        if (m->sec_virt == NULL) {
            continue;
        }
        if (((uintptr_t)sec_virt >= (uintptr_t)m->sec_virt) &&
            ((uintptr_t)sec_virt < ((uintptr_t)m->sec_virt + m->size))) {
            sec_mmb = m;
            break;
        }
    }

    if (sec_mmb == NULL) {
        pr_err("can not find mem, sec_virt:0x%x \n", (uintptr_t)sec_virt);
    }

    return sec_mmb;
}

struct sec_mmb *get_sec_mmb_by_nosecsmmu(unsigned long long nosec_smmu)
{
    struct sec_mmb *sec_mmb = NULL;
    struct sec_mmb *m = NULL, *n = NULL;

    if (!nosec_smmu) {
        pr_err("err args,nosec_smmu:0x%x\n", nosec_smmu);
        return INVIDE_ADDR;
    }

    list_for_each_entry_safe(m, n, &g_smmu_list, list) {
        /*
         * sometimes, the init value of m->nosec_smmu is 0, and this case should be took into account
         * and this case should be avoid
         */
        if (!m->nosec_smmu)
            continue;

        if ((nosec_smmu >= m->nosec_smmu) && (nosec_smmu < (m->nosec_smmu + m->size))) {
            sec_mmb = m;
            break;
        }
    }

    if (sec_mmb == NULL) {
        /*
         * in some times, if sec_mmb is null, it means a new sec_mmb structure
         *
         */
    }

    return sec_mmb;
}

unsigned int replenish_secmmb_info_by_secsmmu(struct sec_mmb *sec_mmb, const char *bufname,
                                              unsigned long long normal_smmu)
{
    int len;

    if (sec_mmb == NULL) {
        pr_err("get_sec_mmb_by_secsmmu failed!\n");
        goto out;
    }

    if (bufname != NULL) {
        len = strlen(bufname) + 1;
        if ((memcpy_s(sec_mmb->name, HIL_MAX_NAME_LEN, bufname,
                      (len > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : len)) != EOK) {
            goto out;
        }
    } else {
        if ((memcpy_s(sec_mmb->name, HIL_MAX_NAME_LEN,  "--", sizeof("--"))) != EOK) {
            goto out;
        }
    }

    if ((sec_mmb->nosec_smmu == 0) && (normal_smmu != 0)) {
        sec_mmb->nosec_smmu = normal_smmu;
    }
    sec_mmb->name[HIL_MAX_NAME_LEN - 1] = '\0';

    return HI_SUCCESS;
out:
    return  HI_FAILED;
}

int ree_ops_alloc_buffer(const char *bufname, unsigned long size, int memtype,
                         struct smmu_ctrl_t *smmu_ctrl_temp)
{
    struct smmu_ctrl_t smmu_ctrl_t = {0};
    int len = 0;
    int ret;
    struct sec_mmb *sec_mmb = NULL;

    if (smmu_ctrl_temp == NULL) {
        pr_err("err args\n");
        goto out;
    }

    smmu_ctrl_t.cmd = HISI_MEM_ALLOC;
    smmu_ctrl_t.memtype = memtype;
    smmu_ctrl_t.size = size;
    smmu_ctrl_t.sec_smmu = smmu_ctrl_temp->sec_smmu;

    if (bufname != NULL) {
        len = strlen(bufname) + 1;
        if ((memcpy_s(smmu_ctrl_t.name, HIL_MAX_NAME_LEN, bufname,
                      (len > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : len)) != EOK) {
            pr_err("memcpy failed\n");
            goto out;
        }
    } else {
        if ((memcpy_s(smmu_ctrl_t.name, HIL_MAX_NAME_LEN, "--", sizeof("--"))) != EOK) {
            pr_err("memcpy failed\n");
            goto out;
        }
    }
    smmu_ctrl_t.name[HIL_MAX_NAME_LEN - 1] = '\0';

    sec_mmb = (struct sec_mmb *)hi_tee_drv_hal_malloc(sizeof(struct sec_mmb));
    if (sec_mmb == NULL) {
        pr_err("hi_tee_drv_hal_malloc failed no mem!");
        goto out;
    }
    if (memset_s((void *)sec_mmb, sizeof(struct sec_mmb), 0x0, sizeof(struct sec_mmb))) {
        goto memset_failed;
    }

    sec_mmb->sec_smmu = smmu_ctrl_t.sec_smmu;
    INIT_LIST_HEAD(&sec_mmb->list);
    INIT_LIST_HEAD(&sec_mmb->t_list);
    if (insert_sec_mmb(sec_mmb) != HI_SUCCESS) {
        goto memset_failed;
    }
    smmu_ctrl_t.handle_id = sec_mmb->handle_id;
    smmu_ctrl_temp->handle_id = sec_mmb->handle_id;

    ret = hi_tee_drv_hal_agentcall(SMMU_AGENT_ID, TA_CALL_AGENT, (void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t));
    if (ret != HI_SUCCESS) {
        pr_err("hi_tee_drv_hal_agentcall failed, ret = %d \n", ret);
        goto exit;
    }

    if ((memcpy_s(smmu_ctrl_temp, sizeof(struct smmu_ctrl_t), &smmu_ctrl_t, sizeof(struct smmu_ctrl_t))) != EOK) {
        pr_err("memcpy failed\n");
        goto err;
    }

    return HI_SUCCESS;

err:
    smmu_ctrl_t.cmd = HISI_MEM_FREE;
    ret = hi_tee_drv_hal_agentcall(SMMU_AGENT_ID, TA_CALL_AGENT,
                                   (void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t));
    if (ret != HI_SUCCESS) {
        pr_err("hi_tee_drv_hal_agentcall failed, ret = %d \n", ret);
    }
exit:
    list_del(&(sec_mmb->list));
memset_failed:
    hi_tee_drv_hal_free((void *)sec_mmb);
out:
    return HI_FAILED;
}

int ree_ops_free_buffer(int memtype, unsigned long long phys_addr,
                        unsigned long long nosec_smmu, unsigned long long sec_smmu, unsigned long long buf_phys)
{
    struct smmu_ctrl_t smmu_ctrl_t = {0};
    int ret;
    struct sec_mmb *sec_mmb = NULL;

    sec_mmb = get_sec_mmb_by_secsmmu(sec_smmu);
    if (sec_mmb == NULL)
        return HI_FAILED;
    smmu_ctrl_t.cmd = HISI_MEM_FREE;
    smmu_ctrl_t.memtype = memtype;
    smmu_ctrl_t.tz_mblock_phys = buf_phys;
    smmu_ctrl_t.normal_smmu = nosec_smmu;
    smmu_ctrl_t.phys_addr = phys_addr;
    smmu_ctrl_t.sec_smmu = sec_smmu;

    ret = hi_tee_drv_hal_agentcall(SMMU_AGENT_ID, TA_CALL_AGENT, (void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t));
    if (ret != HI_SUCCESS) {
        pr_err("hi_tee_drv_hal_agentcall failed, ret = %d \n", ret);
        return HI_FAILED;
    }
    ret = delete_sec_mmb(sec_mmb);
    if (ret) {
        pr_err("delete_sec_mmb failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static inline void smmu_panic(void)
{
    random_delay();
    hi_tee_drv_hal_sys_reset();
    random_delay();
    hi_tee_drv_hal_sys_reset();
    random_delay();
    hi_tee_drv_hal_sys_reset();
}

static inline __attribute__((always_inline)) void pastc_input_param(unsigned long sec_smmu, unsigned long size)
{
    unsigned long sec_smmu_tmp;
    unsigned long size_tmp;

    smmu_write32(PASTC_BSE_REG + PASTC_START_ADDR, (sec_smmu >> HISI_PAGE_SHIFT) * 4);  // 4:smmu addr bit[13:2]
    /* for secure  */
    random_delay();
    sec_smmu_tmp = smmu_read32(PASTC_BSE_REG + PASTC_START_ADDR);
    if (((sec_smmu_tmp / SHIFT_4) << PAGE_SHIFT) != sec_smmu) {
        pr_err("pastc input param fail!\n");
        smmu_panic();
    }
    random_delay();
    sec_smmu_tmp = smmu_read32(PASTC_BSE_REG + PASTC_START_ADDR);
    if (((sec_smmu_tmp / SHIFT_4) << PAGE_SHIFT) != sec_smmu) {
        pr_err("pastc input param fail!\n");
        smmu_panic();
    }
    random_delay();

    /* size is page number  */
    size = (size >> HISI_PAGE_SHIFT) - 1;
    smmu_write32(PASTC_BSE_REG + PASTC_PAGE_NUM, size);
    /* for secure  */
    random_delay();
    size_tmp = smmu_read32(PASTC_BSE_REG + PASTC_PAGE_NUM);
    if (size_tmp != size) {
        pr_err("pastc input param fail!\n");
        smmu_panic();
    }
    random_delay();
    size_tmp = smmu_read32(PASTC_BSE_REG + PASTC_PAGE_NUM);
    if (size_tmp != size) {
        pr_err("pastc input param fail!\n");
        smmu_panic();
    }
}

static inline __attribute__((always_inline)) void pastc_set_secure_attributes()
{
    unsigned int val = 0;
    /* clear secure mode   */
    val = val | 0x11;
    smmu_write32(PASTC_BSE_REG, val);

    /* wait config effective    */
    while (val) {
        val = smmu_read32(PASTC_BSE_REG);
        val = val & 0x1;
    }

    /* check start mode      */
    random_delay();
    val = smmu_read32(PASTC_BSE_REG);
    if ((val & 0x30) != 0x10) {
        pr_err("pastc  set secure attribute fail!\n");
        smmu_panic();
    }
    random_delay();
    val = smmu_read32(PASTC_BSE_REG);
    if ((val & 0x30) != 0x10) {
        pr_err("pastc  set secure attribute fail!\n");
        smmu_panic();
    }
    random_delay();
    val = smmu_read32(PASTC_BSE_REG);
    if ((val & 0x30) != 0x10) {
        pr_err("pastc  set secure attribute fail!\n");
        smmu_panic();
    }
    random_delay();
}

static inline __attribute__((always_inline)) void pastc_clear_secure_attributes()
{
    unsigned int val = 0;
    /* clear secure mode   */
    val = val | 0x21;
    smmu_write32(PASTC_BSE_REG, val);

    /* wait config effective    */
    while (val) {
        val = smmu_read32(PASTC_BSE_REG);
        val = val & 0x1;
    }

    /* check start mode      */
    random_delay();
    val = smmu_read32(PASTC_BSE_REG);
    if ((val & 0x30) != 0x20) {
        pr_err("pastc  clear secure attribute fail!\n");
        smmu_panic();
    }
    random_delay();
    val = smmu_read32(PASTC_BSE_REG);
    if ((val & 0x30) != 0x20) {
        pr_err("pastc  clear secure attribute fail!\n");
        smmu_panic();
    }
    random_delay();
    val = smmu_read32(PASTC_BSE_REG);
    if ((val & 0x30) != 0x20) {
        pr_err("pastc  clear secure attribute fail!\n");
        smmu_panic();
    }
    random_delay();
}

static inline __attribute__((always_inline)) void pastc_check_status()
{
    unsigned int val = 0;

    /* check if config success   */
    val = smmu_read32(PASTC_BSE_REG);
    val = val & 0x4;
    if (val) {
        pr_err("clear secure mem failed!\n");
        smmu_interrupt_handler();
        smmu_panic();
    }
    random_delay();
    val = smmu_read32(PASTC_BSE_REG);
    val = val & 0x4;
    if (val) {
        pr_err("clear secure mem failed!\n");
        smmu_interrupt_handler();
        smmu_panic();
    }
    random_delay();
    val = smmu_read32(PASTC_BSE_REG);
    val = val & 0x4;
    if (val) {
        pr_err("clear secure mem failed!\n");
        smmu_interrupt_handler();
        smmu_panic();
    }
    random_delay();
}


int smmu_set_sec_flags(unsigned long long sec_smmu, unsigned long long size)
{
    struct sec_mmb *sec_mmb = NULL;

    sec_mmb = get_sec_mmb_by_secsmmu(sec_smmu);
    if (sec_mmb == NULL) {
        pr_err("get sec mem failed, sec_smmu:0x%llx \n", sec_smmu);
        goto out;
    }

    pastc_input_param(sec_smmu, size);

    /* set secure mode   */
    pastc_set_secure_attributes();

    /* check if config success   */
    pastc_check_status();

    /* set sec flag */
    sec_mmb->flag = 1;

    return HI_SUCCESS;
out:
    return HI_FAILED;
}

/* clear data in ddr, and clear secure flags  */
int smmu_clear_sec_flags(unsigned long long sec_smmu, unsigned long long size)
{
    struct sec_mmb *sec_mmb = NULL;
    unsigned long long new_smmu;
    int ret = 0;

    sec_mmb = get_sec_mmb_by_secsmmu(sec_smmu);
    if (sec_mmb == NULL) {
        pr_err("get sec mem failed, sec_smmu:0x%x \n", sec_smmu);
        goto out;
    }

    if (!sec_mmb->flag) {
        /*
         * the mem was already clear the sec flag before or the flag is normal
         */
        return HI_SUCCESS;
    }
    /*
     * Here, we map a new smmu range and build map to do the clear secure
     * bit flag. The old smmu map will be clear before starting the hw to
     * do the clear operation. This is more safe.
     */
    new_smmu = hisi_map_smmu(sec_mmb->v_meminfo, sec_mmb->size, sec_mmb->nblocks, (sec_mmb->ssm_tag & 0xff), 0);
    if (new_smmu == INVIDE_ADDR) {
        pr_err("map sec smmu failed and clr secure bit failed, old sec_smmu: 0x%x  size:0x%x\n", sec_smmu, size);
        goto out;
    }
    if (sec_mmb->istagset) {
        ret = tee_drv_ssm_detach_buffer_by_mem(sec_mmb->ssm_tag, sec_mmb->sec_smmu, sec_mmb->sec_smmu + sec_mmb->size);
        if (ret) {
            pr_err("detach failed!\n");
            goto exit;
        }
    }
    sec_mmb->istagset = 0;
    ret = hisi_unamp_smmu((unsigned long long)sec_mmb->sec_smmu, (unsigned long long)sec_mmb->size);
    if (ret == HI_FAILED) {
        pr_err("unmap smmu failed and clr secure bit failed, sec-smmu:0x%lx\n", sec_mmb->sec_smmu);
            goto exit;
    }
    /* set the clear bit    */
    sec_mmb->is_smmu_map_clear = 1;

    pastc_input_param(new_smmu, size);

    /* clear secure mode   */
    pastc_clear_secure_attributes();

    /* check if config success   */
    pastc_check_status();

    /* clear sec flag  */
    sec_mmb->flag = 0;
    hisi_unamp_smmu(new_smmu, sec_mmb->size);

    /* set secure bitmap in mem   */
    if (clear_sec_mem_bitmap(sec_mmb->v_meminfo, sec_mmb->size) != HI_SUCCESS) {
        pr_err("clear sec mem bitmap failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
exit:
    hisi_unamp_smmu(new_smmu, sec_mmb->size);
out:
    return HI_FAILED;
}

int delete_sec_mmb(struct sec_mmb *sec_mmb)
{
    if (sec_mmb == NULL) {
        pr_err("err args \n");
        return HI_FAILED;
    }
    if (sec_mmb->v_meminfo)
        drv_tee_mmz_unmap(sec_mmb->v_meminfo);
    if (sec_mmb->meminfo_addr)
        drv_tee_mmz_delete(sec_mmb->meminfo_addr);
    if (!list_empty(&(sec_mmb->list)))
        list_del(&(sec_mmb->list));
    hi_tee_drv_hal_free((void *)sec_mmb);

    return HI_SUCCESS;
}

static int non_secure_mem_size_calculate(unsigned long long *size)
{
    unsigned long long ddr_start, ddr_end, ddr_size;

    ddr_start = (unsigned long long)hi_tee_drv_mem_get_zone_range(TOTAL_MEM_RANGE, (unsigned long long *)&ddr_size);
    if (!ddr_size) {
        pr_err("get ddr size failed\n");
        return HI_FAILED;
    }

    ddr_end = ddr_start + ddr_size;
    if (ddr_end <= 0x80000000) {
        *size = 0;
    } else if (ddr_end >= 0x100000000) {
        *size = 0x80000000;
    } else {
        *size = ddr_end - 0x80000000;
    }

    return HI_SUCCESS;
}

int ree_mmz_ops_get_meminfo(unsigned long long nonsec_addr, int memtype, struct smmu_ctrl_t *smmu_ctrl_temp)
{
    struct smmu_ctrl_t smmu_ctrl_t;
    int ret;
    struct sec_mmb *sec_mmb = NULL;

    if (smmu_ctrl_temp == NULL) {
        pr_err("err args\n");
        goto out;
    }

    if ((memset_s((void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t), 0x0, sizeof(struct smmu_ctrl_t))) != EOK) {
        pr_err("memset failed\n");
        goto out;
    }

    smmu_ctrl_t.cmd = HISI_MEM_GET_MEMINFO;
    smmu_ctrl_t.memtype = memtype;
    if (memtype) {
        smmu_ctrl_t.normal_smmu = nonsec_addr;
    } else {
        smmu_ctrl_t.phys_addr = nonsec_addr;
    }
    sec_mmb = (struct sec_mmb *)hi_tee_drv_hal_malloc(sizeof(struct sec_mmb));
    if (sec_mmb == NULL) {
        pr_err("hi_tee_drv_hal_malloc failed no mem!");
        goto out;
    }
    if (memset_s((void *)sec_mmb, sizeof(struct sec_mmb), 0x0, sizeof(struct sec_mmb)))
        goto memset_failed;
    INIT_LIST_HEAD(&sec_mmb->list);
    INIT_LIST_HEAD(&sec_mmb->t_list);
    if (insert_sec_mmb(sec_mmb) != HI_SUCCESS)
        goto memset_failed;

    smmu_ctrl_t.handle_id = sec_mmb->handle_id;
    smmu_ctrl_temp->handle_id = sec_mmb->handle_id;
    ret = hi_tee_drv_hal_agentcall(SMMU_AGENT_ID, TA_CALL_AGENT, (void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t));
    if (ret != HI_SUCCESS) {
        pr_err("call agent failed!\n");
        goto exit;
    }

    if (smmu_ctrl_t.tz_mblock_phys == 0) {
        pr_err("call agent failed!\n");
        goto err;
    }

    if ((memcpy_s(smmu_ctrl_temp, sizeof(struct smmu_ctrl_t), &smmu_ctrl_t, sizeof(struct smmu_ctrl_t))) != EOK) {
        pr_err("memcpy failed\n");
        goto err;
    }

    return HI_SUCCESS;

err:
    smmu_ctrl_t.handle_id = sec_mmb->handle_id;
    smmu_ctrl_t.cmd = HISI_MEM_PUT_MEMINFO;
    ret = hi_tee_drv_hal_agentcall(SMMU_AGENT_ID, TA_CALL_AGENT, (void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t));
    if (ret != HI_SUCCESS) {
        pr_err("%s(%d) call failed, ret = %d  \n", __FUNCTION__, __LINE__, ret);
    }
exit:
    list_del(&(sec_mmb->list));
memset_failed:
    hi_tee_drv_hal_free((void *)sec_mmb);
out:
    return HI_FAILED;
}


int ree_mmz_ops_put_meminfo(unsigned long long phys_addr, unsigned long long nosec_smmu,
                            int memtype, unsigned long long buf_phys, unsigned long long handle_id)
{
    struct smmu_ctrl_t smmu_ctrl_t;
    int ret;
    struct sec_mmb *sec_mmb = NULL;

    if ((memset_s((void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t), 0x0, sizeof(struct smmu_ctrl_t))) != EOK) {
        pr_err("memset failed\n");
        return HI_FAILED;
    }

    smmu_ctrl_t.cmd = HISI_MEM_PUT_MEMINFO;
    smmu_ctrl_t.memtype = memtype;
    smmu_ctrl_t.tz_mblock_phys = buf_phys;
    smmu_ctrl_t.normal_smmu = nosec_smmu;
    smmu_ctrl_t.phys_addr = phys_addr;
    smmu_ctrl_t.handle_id = handle_id;
    ret = hi_tee_drv_hal_agentcall(SMMU_AGENT_ID, TA_CALL_AGENT, (void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t));
    if (ret != HI_SUCCESS) {
        pr_err("call agent failed!\n");
        return HI_FAILED;
    }
    sec_mmb = get_sec_mmb_by_handle_id(handle_id);
    if (sec_mmb == NULL) {
        pr_err("get_sec_mmb_by_handle_id failed!\n");
        return HI_FAILED;
    }

    ret = delete_sec_mmb(sec_mmb);
    if (ret) {
        pr_err("del secmmb failed\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}
/*
 * es version chip, logic only initialize secure attr internal sram for phys addr range from 0 to 0x7FFFFFFF
 *    0x80000000 to 0xFFFFFFFF isn't initialized.
 *
 * so secureos should initialize secure attr sram from 0x80000000 to 0xFFFFFFFF
 *    otherwise tzasc fault will be caused
 *
 * */
void non_secure_mem_init(void)
{
    const unsigned long long start = 0x80000000;
    unsigned long long size;
    unsigned int smmu_addr, page_size;
    unsigned int val = 0;

    /* 1.calculate size that need to init */
    if (non_secure_mem_size_calculate(&size) != HI_SUCCESS || size == 0) {
        return;
    }

    /* 2.map phys to sec smmu addr */
    smmu_addr = hisi_map_smmu_by_phys(start, size, 1);
    if (smmu_addr == 0) {
        pr_err("phys mem [0x%llx,0x%llx] map to sec smmu failed\n", start, (start + size));
        return;
    }

    /* 3.set sec smmu flags */
    smmu_write32(PASTC_BSE_REG + PASTC_START_ADDR, (smmu_addr >> HISI_PAGE_SHIFT) * 4); // 4 corrspond shift left 2bit
    page_size = (size >> HISI_PAGE_SHIFT) - 1;
    smmu_write32(PASTC_BSE_REG + PASTC_PAGE_NUM, page_size);
    val = val | 0x11;
    smmu_write32(PASTC_BSE_REG, val);
    while (val) {
        val = smmu_read32(PASTC_BSE_REG);
        val = val & 0x1;
    }
    val = smmu_read32(PASTC_BSE_REG);
    val = val & 0x4;
    if (val) {
        pr_err("set sec smmu flags config failed\n");
        goto err;
    }

    /* 4.clear sec smmu flags */
    smmu_write32(PASTC_BSE_REG + PASTC_START_ADDR, (smmu_addr >> HISI_PAGE_SHIFT) * 4); // 4 corrspond shift left 2bit
    smmu_write32(PASTC_BSE_REG + PASTC_PAGE_NUM, page_size);
    val = val | 0x21;
    smmu_write32(PASTC_BSE_REG, val);
    while (val) {
        val = smmu_read32(PASTC_BSE_REG);
        val = val & 0x1;
    }
    val = smmu_read32(PASTC_BSE_REG);
    val = val & 0x4;
    if (val) {
        pr_err("clear sec smmu flags config failed\n");
        goto err;
    }

err:
    /* 5.unmap sec smmu */
    if (hisi_unamp_smmu(smmu_addr, size)) {
        pr_err("unmap sec smmu failed\n");
    }
}

static int smmu_logic_releate_mem_area_config(unsigned long long smmu_rw_err_addr,
                                              unsigned long long smmu_rw_err_range_size,
                                              unsigned long long smmu_pgtbl_addr,
                                              unsigned long long smmu_pgtbl_size)
{
    void *rw_err = NULL;
    void *pgtbl = NULL;

    if (smmu_rw_err_addr == 0 || smmu_rw_err_range_size == 0 || smmu_pgtbl_addr == 0 || smmu_pgtbl_size == 0) {
        pr_err("err args\n");
        return HI_FAILED;
    }

    /* init dustbin of smmu logic  */
    rw_err = hi_tee_drv_hal_remap((unsigned int)smmu_rw_err_addr, (unsigned int)smmu_rw_err_range_size, true, 0);
    if (rw_err == NULL) {
        pr_err("hi_tee_drv_hal_remap failed!\n");
        return HI_FAILED;
    }
    if ((memset_s(rw_err, smmu_rw_err_range_size, 0x0, smmu_rw_err_range_size)) != EOK) {
        hi_tee_drv_hal_unmap(rw_err, (unsigned int)smmu_rw_err_range_size);
        return HI_FAILED;
    }
    hi_tee_drv_hal_unmap(rw_err, (unsigned int)smmu_rw_err_range_size);

    /* init smmu page table */
    pgtbl = hi_tee_drv_hal_remap((unsigned int)smmu_pgtbl_addr, (unsigned int)smmu_pgtbl_size, true, 0);
    if (pgtbl == NULL) {
        pr_err("hi_tee_drv_hal_remap failed!\n");
        return HI_FAILED;
    }
    if ((memset_s(pgtbl, smmu_pgtbl_size, 0x0, smmu_pgtbl_size)) != EOK) {
        hi_tee_drv_hal_unmap(pgtbl, smmu_pgtbl_size);
        return HI_FAILED;
    }
    hi_tee_drv_hal_unmap(pgtbl, smmu_pgtbl_size);

    return HI_SUCCESS;
}

static int mem_mark_bitmap_init()
{
    int bitmap_size;

    /* init share mem bitmap       */
    bitmap_size = BITS_TO_LONGS(MAX_SHARE_MEM >> HISI_PAGE_SHIFT) * sizeof(long);
    g_sec_mem_bitmap.bitmap = (unsigned long *)hi_tee_drv_hal_malloc(bitmap_size);
    if (g_sec_mem_bitmap.bitmap == NULL) {
        pr_err("alloc mem failed!\n");
        return HI_FAILED;
    }
    if ((memset_s(g_sec_mem_bitmap.bitmap, bitmap_size, 0x0, bitmap_size)) != EOK) {
        goto free_sec_bitmap;
    }
    g_sec_mem_bitmap.bitmap_pfn_base = SHARE_MEM_START >> HISI_PAGE_SHIFT;
    g_sec_mem_bitmap.bitmap_pfn_count = MAX_SHARE_MEM >> HISI_PAGE_SHIFT;

    /* init smmu mem bitmap       */
    bitmap_size = BITS_TO_LONGS((HISI_SEC_SMMU_SIZE >> HISI_PAGE_SHIFT) * sizeof(long));
    bitmap_size = BITS_TO_LONGS((HISI_SEC_SMMU_SIZE >> HISI_PAGE_SHIFT) * sizeof(unsigned long long));
    g_smmu_mem_bitmap.bitmap = (unsigned long *)hi_tee_drv_hal_malloc(bitmap_size);
    if (g_smmu_mem_bitmap.bitmap == NULL) {
        pr_err("alloc mem failed!\n");
        goto free_sec_bitmap;
    }
    if ((memset_s(g_smmu_mem_bitmap.bitmap, bitmap_size, 0x0, bitmap_size)) != EOK) {
        goto free_smmu_bitmap;
    }
    g_smmu_mem_bitmap.bitmap_pfn_base = HISI_SEC_SMMU_BASE >> HISI_PAGE_SHIFT;;
    g_smmu_mem_bitmap.bitmap_pfn_count = HISI_SEC_SMMU_SIZE >> HISI_PAGE_SHIFT;

    return HI_SUCCESS;

free_smmu_bitmap:
    hi_tee_drv_hal_free((void *)g_smmu_mem_bitmap.bitmap);
free_sec_bitmap:
    hi_tee_drv_hal_free((void *)g_sec_mem_bitmap.bitmap);
    return HI_FAILED;
}

static int store_smmu_drv_parameter(unsigned long long smmu_rw_err_addr, unsigned long long smmu_pgtbl_addr)
{
    struct hisi_smmu_domain *hisi_smmu_domain_p = NULL;
    struct sec_smmu *sec_smmu_p = NULL;
    struct hisi_smmu *hisi_smmu = NULL;

    if (smmu_rw_err_addr == 0 || smmu_pgtbl_addr == 0) {
        pr_err("err args\n");
        return HI_FAILED;
    }

    sec_smmu_p = (struct sec_smmu *)hi_tee_drv_hal_malloc(sizeof(struct sec_smmu));
    if (sec_smmu_p == NULL) {
        pr_err("alloc mem failed!\n");
        goto exit;
    }
    sec_smmu_p->r_err_base = ALIGN(smmu_rw_err_addr, SMMU_ERR_RW_SIZE);
    sec_smmu_p->w_err_base = sec_smmu_p->r_err_base + SMMU_ERR_RW_SIZE;
    sec_smmu_p->pgtbl_pbase = smmu_pgtbl_addr;
    sec_smmu_p->pgtbl_size = SMMU_PAGETBL_SIZE;

    hisi_smmu_domain_p = (struct hisi_smmu_domain *)hi_tee_drv_hal_malloc(sizeof(struct hisi_smmu_domain));
    if (hisi_smmu_domain_p == NULL) {
        pr_err(" alloc mem failed!\n");
        goto domain_alloc_err;
    }

    hisi_smmu_domain_p->iova_start = HISI_SEC_SMMU_BASE;
    hisi_smmu_domain_p->iova_size = HISI_SEC_SMMU_SIZE;
    hisi_smmu_domain_p->bitmap_pfn_base = HISI_SEC_SMMU_BASE >> HISI_PAGE_SHIFT;
    hisi_smmu_domain_p->bitmap_pfn_count = HISI_SEC_SMMU_SIZE >> HISI_PAGE_SHIFT;

    hisi_smmu_domain_p->bitmap = g_smmu_mem_bitmap.bitmap;
    if (hisi_smmu_domain_p->bitmap == NULL) {
        goto hisi_smmu_alloc_err;
    }

    hisi_smmu = (struct hisi_smmu *)hi_tee_drv_hal_malloc(sizeof(struct hisi_smmu));
    if (hisi_smmu == NULL) {
        pr_err("alloc mem failed!\n");
        goto hisi_smmu_alloc_err;
    }

    hisi_smmu->pgtbl_addr = NULL;
    hisi_smmu->pgtbl_size = sec_smmu_p->pgtbl_size;
    hisi_smmu->hisi_domain = hisi_smmu_domain_p;
    hisi_smmu->sec_smmu = sec_smmu_p;

    g_hisi_smmu_p = hisi_smmu;

    return HI_SUCCESS;
hisi_smmu_alloc_err:
    hi_tee_drv_hal_free((void *)hisi_smmu_domain_p);
domain_alloc_err:
    hi_tee_drv_hal_free((void *)sec_smmu_p);
exit:
    return HI_FAILED;
}

static void clear_smmu_drv_parameter(void)
{
    struct hisi_smmu *hisi_smmu = NULL;

    hisi_smmu = g_hisi_smmu_p;
    if (hisi_smmu == NULL) {
        pr_err("err args\n");
        return ;
    }

    if (hisi_smmu->hisi_domain == NULL) {
        pr_err("err args\n");
        return ;
    }
    hi_tee_drv_hal_free((void *)hisi_smmu->hisi_domain);

    if (hisi_smmu->sec_smmu == NULL) {
        pr_err("err args\n");
        return;
    }
    hi_tee_drv_hal_free((void *)hisi_smmu->sec_smmu);

    hi_tee_drv_hal_free(hisi_smmu);

    return;
}

static void mem_mark_bitmap_free(void)
{
    hi_tee_drv_hal_free((void *)g_sec_mem_bitmap.bitmap);
    hi_tee_drv_hal_free((void *)g_smmu_mem_bitmap.bitmap);
}

int smmu_init(void)
{
    unsigned long long smmu_rw_err_addr, smmu_rw_err_range_size;
    unsigned long long smmu_pgtbl_addr, smmu_pgtbl_size;
    unsigned long long smmu_start;
    int ret;

    /* step1 : get smmu mem param */
    hi_tee_drv_mem_get_smmu_rw_err_range(&smmu_rw_err_addr, &smmu_rw_err_range_size);
    hi_tee_drv_mem_get_smmu_pgtbl_range(&smmu_pgtbl_addr, &smmu_pgtbl_size);

    /* step2 : set smmu  logic releate mem area to be zero */
    ret = smmu_logic_releate_mem_area_config(smmu_rw_err_addr, smmu_rw_err_range_size,
                                             smmu_pgtbl_addr, smmu_pgtbl_size);
    if (ret != HI_SUCCESS) {
        goto err;
    }

    /* step 3: config SMMU register   */
    ret = smmu_common_init_s(smmu_rw_err_addr, smmu_pgtbl_addr);
    if (ret != HI_SUCCESS) {
        goto err;
    }

    /* step4: create bitmap which wiil be used to mark mem use status */
    ret = mem_mark_bitmap_init();
    if (ret != HI_SUCCESS) {
        goto err;
    }

    /* step 5: store smmu releate parameter which smmu driver need */
    ret = store_smmu_drv_parameter(smmu_rw_err_addr, smmu_pgtbl_addr);
    if (ret != HI_SUCCESS) {
        goto store_param_err;
    }

    /* step6 : get smmu table virt */
    g_hisi_smmu_p->pgtbl_addr = hi_tee_drv_hal_remap((unsigned int)smmu_pgtbl_addr,
                                                     (unsigned int)smmu_pgtbl_size, true, 0);
    if (g_hisi_smmu_p->pgtbl_addr == NULL) {
        goto smmu_table_map_err;
    }

    /* step7: reserved sec-smmu addr spcace */
    smmu_start = _hisi_alloc_smmu_range(HISI_RESERGVED_SEC_SMMU_SPACE_SIZE);
    if (smmu_start != 0) {
        goto smmu_reserve_err;
    }

    /* initialize phys addr from 0x80000000 to 0xFFFFFFFF non secure, avoid tzasc cpu write fault */
    non_secure_mem_init();

    return HI_SUCCESS;

smmu_reserve_err:
    hi_tee_drv_hal_unmap(g_hisi_smmu_p->pgtbl_addr, smmu_pgtbl_size);
smmu_table_map_err:
    clear_smmu_drv_parameter();
store_param_err:
    mem_mark_bitmap_free();
err:
    pr_err("smmu init failed\n");
    return HI_FAILED;
}
