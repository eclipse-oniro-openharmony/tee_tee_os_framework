/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: sec mem config api
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#include "tee_drv_mem_layout.h"
#include "hi_tee_drv_tzasc.h"
#include "hi_tee_drv_os_hal.h"
#include "plat_cfg.h"
#include "platdrv.h"
#include "securec.h"

static unsigned long long g_ddr_total_size = 0ULL;
static unsigned long long g_sec_os_code_base = 0ULL;
static unsigned long long g_sec_os_code_size = 0ULL;

static hi_tee_tzasc_region g_mem_regions[] = {
    {
        .en = 1,
        .base = SEC_OS_START,
        .size = SEC_OS_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_SEC,
        .mid_en = 1,
        .mid_w = RNG_MASTER_SEC_OS_W,
        .mid_r = RNG_MASTER_SEC_OS_R
    },
    {
        .en = 1,
        .base = SEC_MMZ_START,
        .size = SEC_MMZ_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_SEC,
        .mid_en = 1,
        .mid_w = RNG_MASTER_SEC_MMZ_W,
        .mid_r = RNG_MASTER_SEC_MMZ_R
    },
    {
        .en = 1,
        .base = SEC_SMMU_MMZ_START,
        .size = SEC_SMMU_MMZ_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_SEC,
        .mid_en = 1,
        .mid_w = RNG_MASTER_SEC_SMMU_MMZ_W,
        .mid_r = RNG_MASTER_SEC_SMMU_MMZ_R
    },
    {
        .en = 1,
        .base = SEC_SMMU_PAGETABLE_START,
        .size = SEC_SMMU_PAGETABLE_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_SEC,
        .mid_en = 1,
        .mid_w = RNG_MASTER_SMMU_PT_W,
        .mid_r = RNG_MASTER_SMMU_PT_R
    },
    {
        .en = 1,
        .base = ATF_START,
        .size = ATF_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_SEC,
        .mid_en = 1,
        .mid_w = RNG_MASTER_ATF_W,
        .mid_r = RNG_MASTER_ATF_R
    },
    {
        .en = 1,
        .base = SEC_SMMU_RW_ERR_START,
        .size = SEC_SMMU_RW_ERR_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_SEC,
        .mid_en = 1,
        .mid_w = RNG_MASTER_SMMU_ERR_W,
        .mid_r = RNG_MASTER_SMMU_ERR_R
    },
    {
        .en = 1,
        .base = VMCU_START,
        .size = VMCU_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_SEC,
        .mid_en = 1,
        .mid_w = RNG_MASTER_VMCU_W,
        .mid_r = RNG_MASTER_VMCU_R
    },
    {
        .en = 1,
        .base = ADSP_START,
        .size = ADSP_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_SEC,
        .mid_en = 1,
        .mid_w = RNG_MASTER_ADSP_W,
        .mid_r = RNG_MASTER_ADSP_R
    },
    {
        .en = 1,
        .base = VQ6_START,
        .size = VQ6_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_SEC,
        .mid_en = 1,
        .mid_w = RNG_MASTER_VQ6_W,
        .mid_r = RNG_MASTER_VQ6_R
    },
    {
        .en = 1,
        .base = SEC_RESERVE_START,
        .size = SEC_RESERVE_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_SEC,
        .mid_en = 1,
        .mid_w = RNG_MASTER_NONE,
        .mid_r = RNG_MASTER_NONE
    },
    {
        .en = 1,
        .base = EXTRA_REE_MEM_RGN_START,
        .size = EXTRA_REE_MEM_RGN_SIZE,
        .sp = HI_TEE_TZASC_RIGHT_NON_SEC,
        .mid_en = 0,
        .mid_w = RNG_MASTER_NONE,
        .mid_r = RNG_MASTER_NONE
    },
    /* the last region is for extra region */
    {
        0
    },
};

static void tee_drv_mem_random_delay(void)
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

unsigned long long hi_tee_drv_mem_get_zone_range(int zone, unsigned long long *size)
{
    unsigned long long addr = 0;
    unsigned long long zone_size = 0;

    switch (zone) {
        case NON_SEC_OS_MEM:
            addr = SHARE_MEM_START;
            zone_size = SHARE_MEM_SIZE;
            break;
        case SEC_OS_MEM:
            addr = SEC_OS_START;
            zone_size = SEC_OS_SIZE;
            break;
        case SEC_MMZ_MEM:
            addr = SEC_MMZ_START;
            zone_size = SEC_MMZ_SIZE;
            break;
        case NON_SEC_MMZ_MEM: /* not support non secure mmz */
            addr = 0;
            zone_size = 0;
            break;
        case SEC_SMMU_MMZ:
            addr = SEC_SMMU_MMZ_START;
            zone_size = SEC_SMMU_MMZ_SIZE;
            break;
        case SEC_MEM_RANGE:
            addr = TOTAL_TEE_MEM_BASE;
            zone_size = TOTAL_TEE_MEM_SIZE;
            break;
        case TOTAL_MEM_RANGE:
            addr = SHARE_MEM_START;
            zone_size = g_ddr_total_size;
            break;
        case SEC_OS_CODE_RANGE:
            addr = g_sec_os_code_base;
            zone_size = g_sec_os_code_size;
            break;
        case SEC_MEM_VERIFY_RANGE:
            addr = SEC_MEM_VERIFY_REANGE_BASE;
            zone_size = SEC_MEM_VERIFY_REANGE_SIZE;
            break;
        default:
            break;
    }

    if (size != NULL) {
        *size = zone_size;
    }

    return addr;
}

void hi_tee_drv_mem_get_smmu_rw_err_range(unsigned long long *start, unsigned long long *size)
{
    if (start == NULL || size == NULL) {
        return;
    }

    *start = SEC_SMMU_RW_ERR_START;
    *size = SEC_SMMU_RW_ERR_SIZE;
}

void hi_tee_drv_mem_get_smmu_pgtbl_range(unsigned long long *start, unsigned long long *size)
{
    if (start == NULL || size == NULL) {
        return;
    }

    *start = SEC_SMMU_PAGETABLE_START;
    *size = SEC_SMMU_PAGETABLE_SIZE;
}

static int tee_drv_mem_range_check(unsigned long long src, unsigned long long src_size,
                                   unsigned long long tar, unsigned long long tar_size)
{
    unsigned long long src_end = src + src_size;
    unsigned long long tar_end = tar + tar_size;

    if (src_end < src_size || tar_end < tar_size) {
        mem_layout_error("Input overflow\n");
        return 0;
    }

    if (src >= tar && src_end <= tar_end) {
        return 1;
    } else {
        return 0;
    }
}

int hi_tee_drv_mem_is_nonsec(unsigned long long addr, unsigned long long size)
{
    return tee_drv_mem_range_check(addr, size, SHARE_MEM_START, SHARE_MEM_SIZE);
}

int hi_tee_drv_mem_is_sec(unsigned long long addr, unsigned long long size)
{
    return tee_drv_mem_range_check(addr, size, TOTAL_TEE_MEM_BASE, TOTAL_TEE_MEM_SIZE);
}

int hi_tee_drv_mem_is_secmmz(unsigned long long addr, unsigned long long size)
{
    return tee_drv_mem_range_check(addr, size, SEC_MMZ_START, SEC_MMZ_SIZE);
}

static unsigned long long tee_drv_mem_get_ddr_size(void)
{
    if (g_ddr_total_size) {
        return g_ddr_total_size;
    }

#if defined(DRAM0_SIZE)
    g_ddr_total_size = DRAM0_SIZE;
#else
    hi_tee_drv_tzasc_get_share_region_end(&g_ddr_total_size);
#if defined(CFG_HI_TEE_IO_LOW_ADDR_SUPPORT)
    g_ddr_total_size = g_ddr_total_size - SYS_IO_ADDR_SIZE;
#endif
#endif
    mem_layout_debug("ddr total size[%llx]\n", g_ddr_total_size);
    return g_ddr_total_size;
}

static void tee_drv_mem_get_sos_code_range(void)
{
    if (g_sec_os_code_base && g_sec_os_code_size) {
        return;
    }

    hi_tee_drv_hal_get_rodata_pa_range(&g_sec_os_code_base, &g_sec_os_code_size);
}

/*
 * --------------------
 *  reserve region
 * --------------------
 *  second share region
 * --------------------
 *  secure region
 * --------------------
 *  first share region
 * --------------------
 */
static void tee_drv_mem_config_share(void)
{
    unsigned long long board_ddr_size = tee_drv_mem_get_ddr_size();
    hi_tee_tzasc_share_region share_region = {0};
    int region_index = sizeof(g_mem_regions) / sizeof(hi_tee_tzasc_region) - 1;

    /* first share region */
    share_region.en = 1;
    share_region.base = SHARE_MEM_START;
    share_region.size = SHARE_MEM_SIZE;
    share_region.master_type0 = RNG_MASTER_SHARE;
    hi_tee_drv_tzasc_add_share_region(&share_region);

    /* if secure os on the top of ddr, no need to config second share region */
#if defined(CFG_HI_TEE_IO_LOW_ADDR_SUPPORT)
    if ((board_ddr_size + SYS_IO_ADDR_SIZE) <= (TOTAL_TEE_MEM_BASE + TOTAL_TEE_MEM_SIZE)) {
#else
    if (board_ddr_size <= (TOTAL_TEE_MEM_BASE + TOTAL_TEE_MEM_SIZE)) {
#endif
        return;
    }

    /* second share region */
    if (memset_s(&share_region, sizeof(hi_tee_tzasc_share_region), 0, sizeof(hi_tee_tzasc_share_region))) {
        mem_layout_error("memset_s failed!\n");
        hi_tee_drv_hal_panic();
    }

    /* when the io range is in high addr, it's addr range is also in 4G */
    if (board_ddr_size + SYS_IO_ADDR_SIZE <= MAX_SHARE_REGION_END) {
        share_region.en = 1;
        share_region.base = TOTAL_TEE_MEM_BASE + TOTAL_TEE_MEM_SIZE;
        share_region.size = board_ddr_size - SHARE_MEM_SIZE - TOTAL_TEE_MEM_SIZE;
        share_region.master_type0 = RNG_MASTER_SHARE;
        hi_tee_drv_tzasc_add_share_region(&share_region);
    } else {
        share_region.en = 1;
        share_region.base = TOTAL_TEE_MEM_BASE + TOTAL_TEE_MEM_SIZE;
        share_region.size = MAX_SHARE_REGION_END - SHARE_MEM_SIZE - TOTAL_TEE_MEM_SIZE - SYS_IO_ADDR_SIZE;
        share_region.master_type0 = RNG_MASTER_SHARE;
        hi_tee_drv_tzasc_add_share_region(&share_region);

        /* if second share region end exceeds MAX_SHARE_REGION_END, need to config extra region
         * so add the extra region behind the g_mem_regions[]
         */
        g_mem_regions[region_index].en = 1;
#if defined(CFG_HI_TEE_IO_LOW_ADDR_SUPPORT)
        g_mem_regions[region_index].base = MAX_SHARE_REGION_END;
#else
        g_mem_regions[region_index].base = MAX_SHARE_REGION_END - SYS_IO_ADDR_SIZE;
#endif
        g_mem_regions[region_index].size = board_ddr_size + SYS_IO_ADDR_SIZE - MAX_SHARE_REGION_END;
        g_mem_regions[region_index].sp = HI_TEE_TZASC_RIGHT_FULL;
        g_mem_regions[region_index].mid_en = 1;
        g_mem_regions[region_index].mid_w = RNG_MASTER_FULL;
        g_mem_regions[region_index].mid_r = RNG_MASTER_FULL;
    }
}

static void tee_drv_mem_config_sec(void)
{
    int i;
    int region_num = sizeof(g_mem_regions) / sizeof(hi_tee_tzasc_region);

    for (i = 0; i < region_num; i++) {
        if (g_mem_regions[i].size == 0) {
            continue;
        }

        hi_tee_drv_tzasc_add_sec_region(&g_mem_regions[i]);
    }

    /* check the number */
    if (i != region_num) {
        mem_layout_error(" config failed !\n");
        hi_tee_drv_hal_sys_reset();
    }
}

static void tee_drv_mem_config_rodata(void)
{
    hi_tee_tzasc_region region;

    if (memset_s(&region, sizeof(hi_tee_tzasc_region), 0, sizeof(hi_tee_tzasc_region))) {
        mem_layout_error("memset_s failed!\n");
        hi_tee_drv_hal_panic();
    }

    hi_tee_drv_hal_get_rodata_pa_range(&region.base, &region.size);
    if (region.size == 0) {
        mem_layout_error("Get read only data size fail\n");
        hi_tee_drv_hal_panic();
    }

    region.en = 1;
    region.sp = HI_TEE_TZASC_RIGHT_SEC;
    region.mid_en = 1;
    region.mid_w = 0;
    region.mid_r = RNG_MASTER_SEC_OS_R;

    hi_tee_drv_tzasc_add_sec_region(&region);
}

static void tee_drv_mem_config(void)
{
    mem_layout_debug("start memery config\n");

    /*
     * TZASC's sec_bypass do not support config dynamically. When config bypass,
     * MUST make sure no CPU/VDP/logic read or write DDR.
     * Config TZASC's sec_bypass before VDP as follow:
     * reserve region full right -> not bypass -> display LOGO ->
     * share region -> secure region -> reserve region none right.
     */
    /* Config the share region before secure regions */
    tee_drv_mem_config_share();

    tee_drv_mem_config_sec();

    tee_drv_mem_config_rodata();

    /* config share mem release MID */
    hi_tee_drv_tzasc_share_release_config(1, BUS_MASTER_PASTC);
}

static void tee_drv_mem_init(void)
{
    tee_drv_mem_random_delay();
    tee_drv_mem_config();
    hi_tee_drv_tzasc_config_res_region(HI_TEE_TZASC_RIGHT_NONE, BUS_MASTER_CPU);
    hi_tee_drv_tzasc_enable();
}

#ifdef TEE_DRV_MEM_LAYOUT_DEBUG
static void tee_drv_mem_layout_info(void)
{
    mem_layout_printf("--------------------------------------------------------------------\n");
    mem_layout_printf("TEE Mem Layout:\n");
    mem_layout_printf("ATF                  0x%08X - 0x%08X, 0x%X\n", ATF_START, ATF_START + ATF_SIZE, ATF_SIZE);
    mem_layout_printf("SEC SMMU Pagetable   0x%08X - 0x%08X, 0x%X\n", SEC_SMMU_PAGETABLE_START,
                      SEC_SMMU_PAGETABLE_START + SEC_SMMU_PAGETABLE_SIZE, SEC_SMMU_PAGETABLE_SIZE);
    mem_layout_printf("SEC SMMU_MMZ         0x%08X - 0x%08X, 0x%X\n", SEC_SMMU_MMZ_START,
                      SEC_SMMU_MMZ_START + SEC_SMMU_MMZ_SIZE, SEC_SMMU_MMZ_SIZE);
    mem_layout_printf("SEC MMZ              0x%08X - 0x%08X, 0x%X\n", SEC_MMZ_START,
                      SEC_MMZ_START + SEC_MMZ_SIZE, SEC_MMZ_SIZE);
    mem_layout_printf("Secure OS            0x%08X - 0x%08X, 0x%X\n", SEC_OS_START, SEC_OS_START + SEC_OS_SIZE,
                      SEC_OS_SIZE);
    mem_layout_printf("VMCU                 0x%08X - 0x%08X, 0x%X\n", VMCU_START, VMCU_START + VMCU_SIZE, VMCU_SIZE);
    mem_layout_printf("Secure SMMU RW ERR   0x%08X - 0x%08X, 0x%X\n", SEC_SMMU_RW_ERR_START,
                      SEC_SMMU_RW_ERR_START + SEC_SMMU_RW_ERR_SIZE, SEC_SMMU_RW_ERR_SIZE);
    mem_layout_printf("--------------------------------------------------------------------\n");
}
#endif

/* all iomap for devchip_drv */
struct ioaddr_t g_devchip_ioaddrs[] = {
    {REG_BASE_DDRC_PADDR, REG_SIZE_DDRC},
    {REG_BASE_TEE_CTRL_PADDR, REG_SIZE_TEE_CTRL},
    {REG_BASE_RNG_PADDR,    REG_SIZE_RNG },
    {REG_BASE_SPACC_PADDR,  REG_SIZE_SPACC },
    {REG_BASE_KLAD_PADDR, REG_SIZE_KLAD },
    {REG_BASE_RKP_PADDR, REG_SIZE_RKP },
    {REG_BASE_CERT_PADDR, REG_SIZE_CERT },
    {REG_BASE_OTP_PADDR, REG_SIZE_OTP },
    {REG_BASE_OTP_SHADOW_PADDR, REG_SIZE_OTP_SHADOW },
    {REG_BASE_PKE_PADDR,    REG_SIZE_PKE },
    {REG_BASE_SYSRES_PADDR, REG_SIZE_SYSRES},
    {PASTC_BSE_REG_PADDR, PASTC_BSE_SIZE},
    {REG_BASE_SYS_CTRL_PADDR, REG_SIZE_SYS_CTRL},
};

static int32_t platdrv_devchip_map_io(void)
{
    uint32_t i;
    /* prepare io mmap */
    for (i = 0; i < ARRAY_SIZE(g_devchip_ioaddrs); i++) {
        if (g_devchip_ioaddrs[i].base == 0 || g_devchip_ioaddrs[i].size == 0)
            continue;
        void *ptr = hm_io_map(g_devchip_ioaddrs[i].base,
                              (void *)(uintptr_t)(g_devchip_ioaddrs[i].base - OFFSET_PADDR_TO_VADDR),
                              PROT_READ | PROT_WRITE);
        mem_layout_debug("map register %u for driver g_devchip_ioaddrs=%llx %x ptr=%p vaddr=%llx\n", i,
                         g_devchip_ioaddrs[i].base, OFFSET_PADDR_TO_VADDR, ptr,
                         (uintptr_t)(g_devchip_ioaddrs[i].base - OFFSET_PADDR_TO_VADDR));
        if (ptr != (void *)(uintptr_t)(g_devchip_ioaddrs[i].base - OFFSET_PADDR_TO_VADDR)) {
            mem_layout_error("failed to map register %u for driver %llx ,%x\n", i, g_devchip_ioaddrs[i].base, OFFSET_PADDR_TO_VADDR);
            return -1;
        }
    }

    return 0;
}


/* tzasc init */
int hi_tee_drv_mem_config(void)
{
    int32_t ret;
    ret = platdrv_devchip_map_io();
    if (ret != 0) {
		mem_layout_error("platdrv_devchip_map_io failed\n");
        return 1;
    }

    (void)tee_drv_mem_get_ddr_size();
    mem_layout_debug("DDR SIZE: 0x%llX\n", g_ddr_total_size);
#ifdef TEE_DRV_MEM_LAYOUT_DEBUG
    tee_drv_mem_layout_info();
#endif

    tee_drv_mem_get_sos_code_range();
    hi_tee_drv_tzasc_init();
    tee_drv_mem_init();
    tee_drv_mem_random_delay(); /* for security */
    hi_tee_drv_tzasc_config_tzpc();
    tee_drv_mem_random_delay(); /* for security */
    hi_tee_drv_tzasc_security_check();
    return 0;
}

/* for check */
int hi_tee_drv_mem_security_check(void)
{
    hi_tee_drv_tzasc_security_check();

    return 0;
}

static int hi_tee_drv_mem_resume(void)
{
    return hi_tee_drv_mem_config();
}

static int hi_tee_drv_mem_suspend(void)
{
    hi_tee_drv_tzasc_disable();
    return 0;
}

hi_tee_drv_hal_service_init(mem_layout, 0, hi_tee_drv_mem_config, NULL, hi_tee_drv_mem_suspend,
                            hi_tee_drv_mem_resume);
hi_tee_drv_hal_service_init_late(mem_layout_ck, 0, hi_tee_drv_mem_security_check, NULL, NULL,
                                 hi_tee_drv_mem_security_check);
