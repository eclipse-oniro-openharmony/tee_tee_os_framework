/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tzasc hal v400 for 96cv300
 * Author: Hisilicon
 * Create: 2019-06-17
 */


#include "tee_drv_tzasc_v400.h"
#include "tee_drv_tzasc_hal.h"
#include "tee_drv_tzasc_common.h"
#include "hi_tee_drv_tzasc.h"

/* master id is defined by chip bus, shoud be move to platform */
static const char __MAYBE_UNUSED *g_master_str[] = {
/*  0 */    "CPU",
/*  1 */    "GPU",
/*  2 */    "VMCU0",
/*  3 */    "SCIPHER/PandaSHA2",
/*  4 */    "TSHA3/SHA2",
/*  5 */    "SPACC(MCipher)",
/*  6 */    "SDIO0/SDIO1",
/*  7 */    "PCIE0/PCIE1",
/*  8 */    "USB2.0",
/*  9 */    "DDRT0/DDRT1/DDRT2",
/* 10 */    "JPGD",
/* 11 */    "BPD",
/* 12 */    "JPGE",
/* 13 */    "VEDU",
/* 14 */    "PGD",
/* 15 */    "TDE(HWC)",
/* 16 */    "VDP",
/* 17 */    "SPLCIPER",
/* 18 */    "AIAO/QTC",
/* 19 */    "CI",
/* 20 */    "VDH0",
/* 21 */    "SMCU",
/* 22 */    "TSIO",
/* 23 */    "PASTC",
/* 24 */    "Invalid",
/* 25 */    "Invalid",
/* 26 */    "VICAP0/VICAP1",
/* 27 */    "TDMA",
/* 28 */    "VPSS0/VPSS1",
/* 29 */    "AI-DSP0&MAD",
/* 30 */    "PVR(DEMUX)",
/* 31 */    "ETH0/ETH1",
/* 32 */    "DSP1(AD)",
/* 33 */    "IOMMU",
/* 34 */    "NPU",
/* 35 */    "USB3.0/USB3.1",
/* 36 */    "SATA0",
/* 37 */    "UPS",
/* 38 */    "EMMC",
/* 39 */    "FMC",
/* 40 */    "Invalid",
/* 41 */    "Invalid",
/* 42 */    "Invalid",
/* 43 */    "Invalid",
/* 44 */    "VMDA0",
/* 45 */    "VMCU1",
/* 46 */    "VMDA1",
/* 47 */    "Invalid",
/* 48 */    "Invalid",
/* 49 */    "Invalid",
/* 50 */    "Invalid",
/* 51 */    "Invalid",
/* 52 */    "VQ6_DSP0_CORE",
/* 53 */    "VQ6_DSP0_IDMA",
/* 54 */    "VQ6_DSP1_CORE",
/* 55 */    "VQ6_DSP1_IDMA",
};

static int g_sec_region_index = 1;
static int g_share_region_index = 0;

static unsigned int tzasc_size_to_reg(unsigned long long size)
{
    unsigned int size_field;

    size_field = (unsigned int)(size >> TZASC_RNG_ALIGN_SHIFT); /* 64KB(ES) or 4KB(CS FPGA) */

#ifdef CFG_HI_TEE_FPGA_SUPPORT /* CS FPGA */
    tzasc_assert((size_field < 0xFFFFFF) && (size_field > 0));
#else /* ES */
    tzasc_assert((size_field < 0xFFFFF) && (size_field > 0));
#endif
    return size_field;
}

static unsigned int tzasc_sp_to_reg(unsigned int sp)
{
    unsigned int reg = TZASC_SP_NONE;

    switch (sp) {
        case HI_TEE_TZASC_RIGHT_NONE:
            reg = TZASC_SP_NONE;
            break;
        case HI_TEE_TZASC_RIGHT_NON_SEC:
            reg = TZASC_SP_NON_SEC;
            break;
        case HI_TEE_TZASC_RIGHT_SEC:
            reg = TZASC_SP_SEC;
            break;
        case HI_TEE_TZASC_RIGHT_FULL:
            reg = TZASC_SP_FULL;
            break;
        default:
            tzasc_error("Invalid tzasc right\n");
            tzasc_sys_reset();
            break;
    }
    return reg;
}

static void tzasc_sec_access_check(void)
{
    unsigned int __MAYBE_UNUSED int_status, mid, cmdid, access_type, ns, privilege, overrun;
    unsigned int __MAYBE_UNUSED fault_addr_low, fault_addr_high;

    int_status = tzasc_read_bits(SEC_INT_STATUS, _SEC_INT_STATUS_SHIFT, _SEC_INT_STATUS_BITS);
    if (int_status) {
        fault_addr_low = tzasc_read(SEC_FAIL_ADDRESS_LOW);
        fault_addr_high = tzasc_read_bits(SEC_FAIL_STATUS, _SEC_FAIL_CMD_ADDR_HIGH_SHIFT, _SEC_FAIL_CMD_ADDR_HIGH_BITS);
        mid = tzasc_read_bits(SEC_FAIL_ID, _SEC_FAIL_CMD_MID_SHIFT, _SEC_FAIL_CMD_MID_BITS);
        cmdid = tzasc_read_bits(SEC_FAIL_ID, _SEC_FAIL_CMD_ID_SHIFT, _SEC_FAIL_CMD_ID_BITS);
        access_type = tzasc_read_bits(SEC_FAIL_STATUS, _SEC_FAIL_CMD_ACC_TYPE_SHIFT, _SEC_FAIL_CMD_ACC_TYPE_BITS);
        ns = tzasc_read_bits(SEC_FAIL_STATUS, _SEC_FAIL_CMD_NS_SHIFT, _SEC_FAIL_CMD_NS_BITS);
        privilege = tzasc_read_bits(SEC_FAIL_STATUS, _SEC_FAIL_CMD_PRVLG_SHIFT, _SEC_FAIL_CMD_PRVLG_BITS);
        overrun = tzasc_read_bits(SEC_INT_STATUS, _SEC_INT_OVERRUN_SHIFT, _SEC_INT_OVERRUN_BITS);

        tzasc_printf("Fault Access Addr(Reserve Region): 0x%04X %08X\n", fault_addr_high, fault_addr_low);
        tzasc_printf("Fault CMD ID: 0x%X\n", cmdid);
        tzasc_printf("Fault Master ID: 0x%X (%s)\n", mid,
            (mid >= sizeof(g_master_str) / sizeof(g_master_str[0])) ? "Invalid" : g_master_str[mid]);
        tzasc_printf("Fault Access Type: %s\n", access_type ? "write" : "read");
        tzasc_printf("Fault Access From: %s World\n", ns ? "Nonsecure" : "Secure");
        tzasc_printf("Fault Privileged Mode (Only valid for CPU): %s\n", privilege ? "Privileged" : "Unprivileged");
        tzasc_printf("Fault More than one times: %s\n", overrun ? "Yes" : "No");
    }
}

static void tzasc_share_access_check(void)
{
    unsigned int __MAYBE_UNUSED share_fail_status, mid, cmdid, access_type, ns, share_access_over_release;
    unsigned int __MAYBE_UNUSED fault_addr_low, fault_addr_high;
    unsigned long long fault_addr;

    share_fail_status = tzasc_read_bits(SEC_SHARE_RGN_FAIL_CMD_STATUS, _SEC_SHARE_RGN_FAIL_CMD_STATUS_SHIFT,
                                        _SEC_SHARE_RGN_FAIL_CMD_STATUS_BITS);
    if (share_fail_status) {
        fault_addr_low = tzasc_read(SEC_SHARE_RGN_FAIL_CMD_ADDR);
        fault_addr_high = tzasc_read_bits(SEC_SHARE_RGN_FAIL_CMD_INFO, _SEC_SHARE_RGN_FAIL_CMD_ADDR_HIGH_SHIFT,
                                          _SEC_SHARE_RGN_FAIL_CMD_ADDR_HIGH_BITS);

        fault_addr = (fault_addr_high << 31) | (fault_addr_low >> 1); /* high addr shift left 31 bit */
        mid = tzasc_read_bits(SEC_SHARE_RGN_FAIL_CMD_INFO, _SEC_SHARE_RGN_FAIL_CMD_MID_SHIFT,
                              _SEC_SHARE_RGN_FAIL_CMD_MID_BITS);
        cmdid = tzasc_read_bits(SEC_SHARE_RGN_FAIL_CMD_INFO, _SEC_SHARE_RGN_FAIL_CMD_ID_SHIFT,
                                _SEC_SHARE_RGN_FAIL_CMD_ID_BITS);
        access_type = tzasc_read_bits(SEC_SHARE_RGN_FAIL_CMD_INFO, _SEC_SHARE_RGN_FAIL_CMD_ACC_TYPE_SHIFT,
                                      _SEC_SHARE_RGN_FAIL_CMD_ACC_TYPE_BITS);
        ns = tzasc_read_bits(SEC_SHARE_RGN_FAIL_CMD_INFO, _SEC_SHARE_RGN_FAIL_CMD_NS_SHIFT,
                             _SEC_SHARE_RGN_FAIL_CMD_NS_BITS);
        share_access_over_release = tzasc_read_bits(SEC_SHARE_RELEASE_MID, _SEC_SHARE_RGN_FAIL_CMD_LOCK_MID_SHIFT,
                                                    _SEC_SHARE_RGN_FAIL_CMD_LOCK_MID_BITS);

        tzasc_printf("Fault Access Addr(Share Region): 0x%012llx\n", fault_addr);
        tzasc_printf("Fault CMD ID: 0x%X\n", cmdid);
        tzasc_printf("Fault Master ID: 0x%X (%s)\n", mid,
            (mid >= sizeof(g_master_str) / sizeof(g_master_str[0])) ? "Invalid" : g_master_str[mid]);
        tzasc_printf("Fault Access Type: %s\n", access_type ? "write" : "read");
        tzasc_printf("Fault Access From: %s World\n", ns ? "Nonsecure" : "Secure");
        tzasc_printf("Fault Access over release mem: %s\n", share_access_over_release ? "Yes" : "No");
    }
}

static int tzasc_interrupt_handle(int arg)
{
    (void)arg;

    tzasc_printf("------------------------------------------------------------------\n");
    tzasc_printf("Warning: Unauthorized read/write operation detected!!\n");

    tzasc_sec_access_check();
    tzasc_share_access_check();

    tzasc_dump_addr("TZPC", (char *)SEC_DDRC_CTRL_REG, 0x40);
    tzasc_dump_addr("TZASC", (char *)REG_BASE_TZASC, 0x3C0);

    tzasc_write(0x12345678, SEC_INT_CLEAR); /* clear interrupt */

    return HI_TEE_HAL_IRQ_HANDLED;
}

static void tzasc_config_interrupt(void)
{
    /* mask read irq to report response error */
    tzasc_sec_write((unsigned int)TZASC_RSP_MSK_MID_R, SEC_RSP_MSK_RMID);
    tzasc_sec_write((unsigned int)((TZASC_RSP_MSK_MID_R >> 16) >> 16), SEC_RSP_MSK_RMID_EXT); /* 16 * 2, 32bit */

    /* mask read int */
    tzasc_sec_write((unsigned int)TZASC_INT_MSK_MID_R, SEC_INT_MSK_RMID);
    tzasc_sec_write((unsigned int)((TZASC_INT_MSK_MID_R >> 16) >> 16), SEC_INT_MSK_RMID_EXT); /* 16 * 2, 32bit */

    tzasc_write(0x12345678, SEC_INT_CLEAR); /* clear interrupt */
    (void)tzasc_request_irq(SEC_TZASC_ERR_IRQ, (void *)tzasc_interrupt_handle, (void *)0);
    tzasc_set_bit(SEC_INT_EN, _SEC_INT_EN_SHIFT); /* enable interrupt */
}

void tzasc_hal_config_res_region(unsigned int sp, unsigned long long mid)
{
    /* region0 is always enable and region0 donot need to config */
    (void)sp;
    (void)mid;
}

void tzasc_hal_add_sec_region(hi_tee_tzasc_region *region)
{
    int i = g_sec_region_index;
    unsigned long long region_base = region->base;
    unsigned long long region_size = region->size;

    tzasc_assert(region->base < (region->base + region->size));
    tzasc_assert(region->base < (region->base + TZASC_RNG_ALIGN_BLOCK));
    tzasc_assert(region->size < MAX_DDR_SIZE);
    tzasc_assert(i < MAX_SEC_REGIONS);

    tzasc_debug("region[%d] base[0x%llX] size[0x%llX] sp[0x%X] mid_en[0x%X] mid_w[0x%llX] mid_r[0x%llX]\n",
        i, region->base, region->size, region->sp, region->mid_en, region->mid_w, region->mid_r);

    /* region base addr and region size must align 64KB(ES) or 4KB(CS) */
    tzasc_assert((region_base & (TZASC_RNG_ALIGN_BLOCK - 1)) == 0);
    tzasc_assert((region_size & (TZASC_RNG_ALIGN_BLOCK - 1)) == 0);

    /* Set region base addr */
    tzasc_write_bits(SEC_RGN_MAP(i),
                     (unsigned int)((region->base + TZASC_RNG_ALIGN_BLOCK - 1) >> TZASC_RNG_ALIGN_SHIFT),
                     _SEC_RGN_BASE_ADDR_SHIFT, _SEC_RGN_BASE_ADDR_BITS);

    /* Set region size */
    tzasc_write_bits(SEC_RGN_MAP_EXT(i), tzasc_size_to_reg(region->size), _SEC_RGN_SIZE_SHIFT, _SEC_RGN_SIZE_BITS);

    /* Enable region sec inv */
    tzasc_set_bit(SEC_RGN_ATTR(i), _SEC_RGN_SEC_INV_SHIFT);
    tzasc_write_bits(SEC_RGN_ATTR(i), tzasc_sp_to_reg(region->sp), _SEC_RGN_SP_SHIFT, _SEC_RGN_SP_BITS);

    /* If mid match needed, set the mid_w and mid_r reg */
    if (region->mid_en) {
        tzasc_set_bit(SEC_RGN_ATTR(i), _SEC_RGN_MID_EN_SHIFT);

        tzasc_sec_write((unsigned int)region->mid_w, SEC_RGN_MID_W(i));
        tzasc_sec_write((unsigned int)((region->mid_w >> 16) >> 16), SEC_RGN_MID_W_EXT(i)); /* 16 * 2, high 32bits */
        tzasc_sec_write((unsigned int)region->mid_r, SEC_RGN_MID_R(i));
        tzasc_sec_write((unsigned int)((region->mid_r >> 16) >> 16), SEC_RGN_MID_R_EXT(i)); /* 16 * 2, high 32bits */
    }

    /* Enable region */
    tzasc_set_bit(SEC_RGN_MAP(i), _SEC_RGN_EN_SHIFT);
    /* check enable   */
    tzasc_assert(tzasc_get_bit(SEC_RGN_MAP(i), _SEC_RGN_EN_SHIFT));
    tzasc_random_delay();
    tzasc_assert(tzasc_get_bit(SEC_RGN_MAP(i), _SEC_RGN_EN_SHIFT));
    tzasc_random_delay();
    tzasc_assert(tzasc_get_bit(SEC_RGN_MAP(i), _SEC_RGN_EN_SHIFT));

    g_sec_region_index++;
}

void tzasc_hal_add_share_region(hi_tee_tzasc_share_region *region)
{
    unsigned long long base, size;

    tzasc_assert(g_share_region_index < MAX_SHARE_REGIONS);

    tzasc_debug("share region[%d] base[0x%llX] size[0x%llX] master[0x%llX]\n",
        g_share_region_index, region->base, region->size, region->master_type0);

    tzasc_assert(region->en);

    base = (region->base + TZASC_RNG_ALIGN_BLOCK - 1) & (~((1ULL << TZASC_RNG_ALIGN_SHIFT) - 1));
    size = (region->size + TZASC_RNG_ALIGN_BLOCK - 1) & (~((1ULL << TZASC_RNG_ALIGN_SHIFT) - 1));

    tzasc_assert(base < (base + size));
    tzasc_assert(base < (base + TZASC_RNG_ALIGN_BLOCK));
    tzasc_assert(size < MAX_DDR_SIZE);

    /*
     * There is a 64k(ES) or 4k(CS) mem gap between the shared region and reserved region.
     * And the real mem end to be assecc is (end(config to register) + 64k or 4k).
     */
    if (g_share_region_index == 0) {
        size = size - TZASC_RNG_ALIGN_BLOCK;
    }
    if (g_share_region_index == 1) {
        base = base + TZASC_RNG_ALIGN_BLOCK;
        size = size - TZASC_RNG_ALIGN_BLOCK;
    }

    tzasc_sec_write((unsigned int)(base >> TZASC_RNG_ALIGN_SHIFT), SEC_SHARE_RGN_START(g_share_region_index));
    tzasc_sec_write((unsigned int)((base + size) >> TZASC_RNG_ALIGN_SHIFT), SEC_SHARE_RGN_END(g_share_region_index));

    tzasc_set_bit(SEC_SHARE_RGN_EN(g_share_region_index), _SEC_SHARE_RGN_EN_SHIFT);

    /* Config the master type for share region */
    tzasc_sec_write((unsigned int)region->master_type0, SEC_MASTER_TYPE_SHARE);
    tzasc_sec_write((unsigned int)((region->master_type0 >> 16) >> 16), SEC_MASTER_TYPE_SHARE_EXT); /* 16 * 2, 32bit */

    g_share_region_index++;
}

void tzasc_hal_share_release_config(const unsigned int en, unsigned long long mid)
{
    unsigned int release_mid = 0;
    unsigned int i;

    if (en == 0) {
        return;
    }

    /* config share release mid */
    for (i = 0; i < sizeof(mid) * 8; i++) { /* 1byte is 8 bits */
        if ((mid >> i) & 0x01) {
            release_mid = i;
            break;
        }
    }
    tzasc_write_bits(SEC_SHARE_RELEASE_MID, release_mid, _SEC_SHARE_RELEASE_MID_SHIFT, _SEC_SHARE_RELEASE_MID_BITS);

    /* Enable share release lock */
    tzasc_set_bit(SEC_SHARE_RELEASE_MID, _SEC_SHARE_RELEASE_EN_SHIFT);
}

void tzasc_hal_enable(void)
{
    unsigned int lockdown_sel;

    /* config tzasc interrupt */
    tzasc_config_interrupt();

    /* Not bypass TZASC. It have been set in boot, set again for ensure. */
    tzasc_write_bits(SEC_BYPASS, 0x5A, _SEC_BYPASS_SHIFT, _SEC_BYPASS_BITS);
    tzasc_random_delay(); /* for security */
    tzasc_write_bits(SEC_BYPASS, 0x5A, _SEC_BYPASS_SHIFT, _SEC_BYPASS_BITS);
    tzasc_random_delay();

    tzasc_assert(tzasc_read_bits(SEC_BYPASS, _SEC_BYPASS_SHIFT, _SEC_BYPASS_BITS) == 0x5A);

#ifndef CFG_HI_TEE_FPGA_SUPPORT
    /* Set the lockdown selection */
    lockdown_sel = tzasc_read(SEC_LOCKDOWN_SEL);
    lockdown_sel |= _SEC_LOCKDOWN_SEL_CFG;
    tzasc_sec_write(lockdown_sel, SEC_LOCKDOWN_SEL);
    tzasc_random_delay(); /* for security */

    tzasc_assert(lockdown_sel == tzasc_read(SEC_LOCKDOWN_SEL));
#endif
}

void tzasc_hal_disable(void)
{
    /* disable tzasc interrupt     */
    tzasc_unregister_irq(SEC_TZASC_ERR_IRQ);
}

void tzasc_hal_config_tzpc(void)
{
#ifndef CFG_HI_TEE_FPGA_SUPPORT
    /* lock down tzasc/tzpc config */
    tzasc_set_bit(SEC_DDRC_CTRL_REG, _SEC_BOOT_LOCK_SHIFT);

    tzasc_random_delay(); /* for security */
    tzasc_assert(tzasc_get_bit(SEC_DDRC_CTRL_REG, _SEC_BOOT_LOCK_SHIFT) == 1);
#endif

#ifdef TEE_DRV_TZASC_DEBUG
#ifndef CFG_HI_TEE_FPGA_SUPPORT
    tzasc_dump_addr("TZPC", (char *)SEC_DDRC_CTRL_REG, 0x40);
#endif
    tzasc_dump_addr("TZASC", (char *)REG_BASE_TZASC, 0x3C0);
#endif
}

void tzasc_hal_security_check(void)
{
    /* check sec bypass */
    tzasc_assert(get_bits_shift(tzasc_read(SEC_BYPASS), _SEC_BYPASS_BITS, _SEC_BYPASS_SHIFT) == 0x5A);
    tzasc_random_delay(); /* for security */
    tzasc_assert(get_bits_shift(tzasc_read(SEC_BYPASS), _SEC_BYPASS_BITS, _SEC_BYPASS_SHIFT) == 0x5A);
    tzasc_random_delay(); /* for security */
    tzasc_assert(get_bits_shift(tzasc_read(SEC_BYPASS), _SEC_BYPASS_BITS, _SEC_BYPASS_SHIFT) == 0x5A);

#ifndef CFG_HI_TEE_FPGA_SUPPORT
    /* check sec lock */
    tzasc_random_delay(); /* for security */
    tzasc_assert(get_bits_shift(tzasc_read(SEC_DDRC_CTRL_REG), 1, _SEC_BOOT_LOCK_SHIFT) == 1);
    tzasc_random_delay(); /* for security */
    tzasc_assert(get_bits_shift(tzasc_read(SEC_DDRC_CTRL_REG), 1, _SEC_BOOT_LOCK_SHIFT) == 1);
    tzasc_random_delay(); /* for security */
    tzasc_assert(get_bits_shift(tzasc_read(SEC_DDRC_CTRL_REG), 1, _SEC_BOOT_LOCK_SHIFT) == 1);
#endif
}

void tzasc_hal_init(void)
{
    g_sec_region_index = 1;
    g_share_region_index = 0;
}

void tzasc_hal_get_share_region_end(unsigned long long *addr)
{
    unsigned int max_end = 0;
    unsigned int share_region_end = 0;
    int i;

    /* share region has been config before SecureOS start */
    for (i = 0; i < MAX_SHARE_REGIONS; i++) {
        share_region_end = tzasc_read(SEC_SHARE_RGN_END(i));
        if (max_end < share_region_end) {
            max_end = share_region_end;
        }
    }
#ifdef TEE_DRV_TZASC_DEBUG
#ifndef CFG_HI_TEE_FPGA_SUPPORT
    tzasc_dump_addr("TZPC", (char *)SEC_DDRC_CTRL_REG, 0x40);
#endif
    tzasc_dump_addr("TZASC", (char *)REG_BASE_TZASC, 0x3C0);
#endif
    tzasc_assert(max_end != 0);
    *addr = ((unsigned long long)max_end << TZASC_RNG_ALIGN_SHIFT);
}
