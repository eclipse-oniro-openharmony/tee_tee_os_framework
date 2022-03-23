/*
  * hisilicon efuse driver, hisi_efuse.c
  *
  * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
  *
  */

#include <register_ops.h>
#include <sre_debug.h>
#include <sre_typedef.h>
#include <mem_ops.h>
#include "secboot.h"
#include "tee_log.h"
#include <hi_efuse.h>
#include <bsp_modem_call.h>
#include "hisi_efuse.h"
#include <drv_module.h>

#include "product_config.h"

#ifndef UNUSED
#define UNUSED(param) (void)param;
#endif

extern unsigned int SEB_ReadOTPWord(unsigned int group, unsigned int *value);
extern unsigned int SEB_WriteOTPWord(unsigned int group, unsigned int value);
extern unsigned int SEB_SetPubKeyHash(unsigned long long certStoreAddress, unsigned int *pWorkspace, unsigned int workspaceSize);
extern unsigned int SEB_CalcPublicKeyHASH(unsigned long long certStoreAddress, unsigned int *pWorkspace, unsigned int workspaceSize, unsigned *hbk);
extern unsigned int SEB_DmpuUnpack(unsigned *hbk, unsigned *seckce, unsigned *kce);
extern unsigned int SEB_SetKce(unsigned int *kce_value);

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI9500)
#define HI_EFUSE_SYSCTRL_BASE_ADDR  0xEDF07000
#define EFUSE_APB_MAX               64
#define EFUSE_AIB_MAX               32

unsigned int efuse_read_mask[EFUSE_MAX_SIZE] = {
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x80030000,0xFFFFFFFF,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0x0,0x0,0x0,0x0,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
};

unsigned int efuse_write_mask[EFUSE_MAX_SIZE] = {
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x80030000,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
};
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI9510)
#define HI_EFUSE_SYSCTRL_BASE_ADDR  0xEDF07000
#define EFUSE_APB_MAX               128
#define EFUSE_AIB_MAX               32

unsigned int efuse_read_mask[EFUSE_MAX_SIZE] = {
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x80030000,0xFFFFFFFF,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0x0,0x0,0x0,0x0,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
};

unsigned int efuse_write_mask[EFUSE_MAX_SIZE] = {
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x80030000,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
    0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
};
#endif

#define DX_KCE_LENGTH            EFUSE_LAYOUT_KCE_LENGTH
#define DX_HBK_LENGTH            8
#define DX_SECKCE_LENGTH         EFUSE_LAYOUT_SECKCE_LENGTH
#define MAX_EFUSE_DELAY          0x1000000

unsigned int g_efuse_dieid[EFUSE_DIEID_SIZE];
static unsigned g_efuse_buffer[EFUSE_MAX_SIZE] = {0};
static unsigned g_efuse_remap_status = 0;

/* 直接读32bit的时候不可使用，1<<32编译器可能会有未定义的行为 */
static unsigned osl_reg_get_bit(unsigned long reg, unsigned bit_start, unsigned bit_end)
{
    unsigned tmp;
    tmp = readl((unsigned)reg);
    return ((tmp >> bit_start)&((1U << (bit_end - bit_start + 1U))-1U));
}

static void osl_reg_set_bit(unsigned long reg, unsigned bit_start, unsigned bit_end, unsigned reg_val)
{
    unsigned tmp;
    tmp = readl((unsigned)reg);
    tmp &= (~(((1U << (bit_end - bit_start + 1U))-1U) << bit_start));
    tmp |= (reg_val << bit_start);
    writel(tmp, (unsigned)reg);
}

static void bsp_efuse_enable_remap(void)
{
    if (g_efuse_remap_status) {
        osl_reg_set_bit(HI_ACORE_SC_AO_CTRL0, HI_EFUSEC_REMAP_BIT, HI_EFUSEC_REMAP_BIT, 1);
    }
}

static void bsp_efuse_disable_remap(void)
{
    if (g_efuse_remap_status) {
        osl_reg_set_bit(HI_ACORE_SC_AO_CTRL0, HI_EFUSEC_REMAP_BIT, HI_EFUSEC_REMAP_BIT, 0);
    }
}

static unsigned bsp_efuse_get_remap_status(void)
{
    return osl_reg_get_bit(HI_ACORE_SC_AO_CTRL0, HI_EFUSEC_REMAP_BIT, HI_EFUSEC_REMAP_BIT);
}

void bsp_efuse_flush_sram(u32 group, u32 len)
{
    int ret;
    u32 i;
    u32 value;

    if (!g_efuse_remap_status) {
        return;
    }

    value = 0;

    for (i = group; i < group + len; i++) {
        ret = bsp_efuse_apb_read(&value, i, 1);
        if (ret) {
            g_efuse_remap_status = 0;
            tloge("efuse flush sram err %d.\n", ret);
            return;
        }
    }

    return;
}

int bsp_efuse_apb_exit_pd(void)
{
    int ret = 0;
    unsigned int delay;
    unsigned int value = 0;

    if (osl_reg_get_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_STATUS_OFFSET, HI_EFUSE_PD_STAT_BIT, HI_EFUSE_PD_STAT_BIT)) {

        osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_CFG_OFFSET, HI_EFUSE_PD_EN_BIT, HI_EFUSE_PD_EN_BIT, 0);

        delay = MAX_EFUSE_DELAY;
        do {
            value = osl_reg_get_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_STATUS_OFFSET, HI_EFUSE_PD_STAT_BIT, HI_EFUSE_PD_STAT_BIT);
        } while ((value == 1) && (--delay));

        if (!delay) {
            tloge("EFUSE_ERROR_EXIT_PD_TIMEOUT.\n");
            return -1;
        }
    }

    return ret;
}

int bsp_efuse_apb_read(unsigned int *pBuf, const unsigned int group, const unsigned int num)
{
    int ret;
    unsigned int delay;
    unsigned int count;
    unsigned int value = 0;

    ret = bsp_efuse_apb_exit_pd();
    if (ret) {
        return ret;
    }

    osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_CFG_OFFSET, HI_EFUSE_AIB_SEL_BIT, HI_EFUSE_AIB_SEL_BIT, 1);

    for (count = 0; count < num; count++) {
        osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSE_GROUP_OFFSET, HI_EFUSE_GROUP_LBIT, HI_EFUSE_GROUP_HBIT, group+count);

        osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_CFG_OFFSET, HI_EFUSE_RD_EN_BIT, HI_EFUSE_RD_EN_BIT, 1);

        delay = MAX_EFUSE_DELAY;
        do {
            value = osl_reg_get_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_STATUS_OFFSET, HI_EFUSE_RD_STAT_BIT, HI_EFUSE_RD_STAT_BIT);
        } while ((value == 0) && (--delay));

        if (!delay) {
            tloge("EFUSE_ERROR_READ_TIMEOUT.\n");
            return -1;
        }

        *pBuf = readl(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_DATA_OFFSET);
        pBuf++;
    }

    osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_CFG_OFFSET, HI_EFUSE_AIB_SEL_BIT, HI_EFUSE_AIB_SEL_BIT, 0);

    return ret;
}

int bsp_efuse_apb_write(unsigned int *pBuf, const unsigned int group, const unsigned int len)
{
    int ret = -1;
    unsigned int delay;
    unsigned int count;
    unsigned int value = 0;

    if (osl_reg_get_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_HW_CFG_OFFSET, HI_EFUSE_DISFLAG_BIT, HI_EFUSE_DISFLAG_BIT)) {
        tloge("write is disable.\n");
        goto efuse_write_error;
    }

    ret = bsp_efuse_apb_exit_pd();
    if (ret) {
        goto efuse_write_error;
    }

    osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_CFG_OFFSET, HI_EFUSE_AIB_SEL_BIT, HI_EFUSE_AIB_SEL_BIT, 1);
    osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_COUNT_OFFSET, HI_EFUSE_COUNT_LBIT, HI_EFUSE_COUNT_HBIT, EFUSE_COUNT_CFG);
    osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_PGM_COUNT_OFFSET, HI_EFUSE_PGM_COUNT_LBIT, HI_EFUSE_PGM_COUNT_HBIT, PGM_COUNT_CFG);
    osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_CFG_OFFSET, HI_EFUSE_PRE_PG_BIT, HI_EFUSE_PRE_PG_BIT, 1);

    delay = MAX_EFUSE_DELAY;
    do{
        value = osl_reg_get_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_STATUS_OFFSET, HI_EFUSE_PGENB_STAT_BIT, HI_EFUSE_PGENB_STAT_BIT);
    } while ((value == 0) && (--delay));

    if (!delay) {
        ret = -1;
        tloge("EFUSE_ERROR_PRE_WRITE_TIMEOUT.\n");
        goto efuse_write_error;
    }

    for (count = 0; count < len; count++) {
        osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSE_GROUP_OFFSET, HI_EFUSE_GROUP_LBIT, HI_EFUSE_GROUP_HBIT, group+count);
        value = *pBuf;
        writel(value, HI_EFUSE_SYSCTRL_BASE_ADDR + HI_PG_VALUE_OFFSET);
        osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_CFG_OFFSET, HI_EFUSE_PGEN_BIT, HI_EFUSE_PGEN_BIT, 1);

        delay = MAX_EFUSE_DELAY;
        do{
            value = (unsigned)osl_reg_get_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_STATUS_OFFSET, HI_EFUSE_PG_STAT_BIT, HI_EFUSE_PG_STAT_BIT);
        } while ((value == 0) && (--delay));

        if (!delay) {
            ret = -1;
            tloge("EFUSE_ERROR_EXIT_PD_TIMEOUT.\n");
            goto efuse_write_error;
        }

        pBuf++;
    }

efuse_write_error:
    osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_CFG_OFFSET, HI_EFUSE_AIB_SEL_BIT, HI_EFUSE_AIB_SEL_BIT, 0);
    osl_reg_set_bit(HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSEC_CFG_OFFSET, HI_EFUSE_PRE_PG_BIT, HI_EFUSE_PRE_PG_BIT, 0);
    bsp_efuse_flush_sram(group, len);

    return ret;
}

int bsp_sec_call_efuse_read(unsigned int cmd, void *arg2, unsigned int arg3)
{
    int i = 0;
    int ret = 0;
    unsigned int value = 0;
    unsigned int *virt_buffer_addr = NULL;

    UNUSED(cmd);
    UNUSED(arg3);
    virt_buffer_addr = (unsigned int *)arg2;

    for (i = 0; i < EFUSE_LAYOUT_MP_FLAG_OFFSET; i++) {
        *(virt_buffer_addr + i) = 0;
    }

    for (i = EFUSE_LAYOUT_MP_FLAG_OFFSET; i < EFUSE_AIB_MAX; i++) {
        value = 0;
        ret = bsp_efuse_aib_read(&value, i, 1);
        *(virt_buffer_addr + i) = value & efuse_read_mask[i];
        if (ret) {
            tloge("fail to read OTP memory, group = 0x%X ret = 0x%X\n", (unsigned int)i, (unsigned int)ret);
            goto error_read_otp;
        }
    }

    for (i = EFUSE_AIB_MAX; i < EFUSE_APB_MAX; i++) {
        value = 0;
        ret = bsp_efuse_apb_read(&value, i, 1);
        *(virt_buffer_addr + i) = value & efuse_read_mask[i];
        if (ret) {
            tloge("fail to read OTP memory, group = 0x%X ret = 0x%X\n", (unsigned int)i, (unsigned int)ret);
            goto error_read_otp;
        }
    }
error_read_otp:
    return ret;
}

static int value_is_valid(unsigned int *base_addr, int size)
{
    int i;
    for (i = 0; i < size; i++) {
        if (base_addr[i] != 0) {
            return -1;
        }
    }

    return 0;
}

int efuse_huk_valid_check(unsigned int buffer_addr)
{
    int ret;
    unsigned int value[EFUSE_HUK_SIZE] = {0};
    if (value_is_valid((unsigned int *)(uintptr_t)(buffer_addr + EFUSE_GRP_HUK * 4), EFUSE_HUK_SIZE)) {
        ret = bsp_efuse_apb_read(&value[0], EFUSE_GRP_HUK, EFUSE_HUK_SIZE);
        if (ret) {
            tloge("fail to read efuse. ret = %d\n", ret);
            return ret;
        }

        if (value_is_valid(&value[0], EFUSE_HUK_SIZE)) {
            tloge("already set huk, only allow write once.\n");
            return -1;
        }
    }
    return 0;
}

int efuse_sec_group_burn(unsigned int buffer_addr)
{
    int ret;
    unsigned int value[2] = {0};
    if (value_is_valid((unsigned int *)(uintptr_t)(buffer_addr + EFUSE_LAYOUT_KCE_OFFSET * 4),
        EFUSE_LAYOUT_KCE_LENGTH)) {
        ret = (int)SEB_SetKce((unsigned *)(uintptr_t)(buffer_addr + EFUSE_LAYOUT_KCE_OFFSET * 4));
        if (ret) {
            tloge("fail to set kce. ret = %d\n", ret);
            return ret;
        }
    }

    if ((((*(unsigned int *)(uintptr_t)(buffer_addr + EFUSE_LAYOUT_MP_FLAG_OFFSET * 4)) >>
        EFUSE_LAYOUT_MP_FLAG_LCS_BIT_OFFSET) &
        0xF) == 0x3) {
        ret = (int)SEB_SetPubKeyHash(VRL_ADDR, SECBOOT_DX_WORKSPACE_ADDR, SECBOOT_DX_WORKSPACE_SIZE);
        if (ret) {
            tloge("fail to set pubkey. ret = %d\n", ret);
            return ret;
        }
    }

    if ((*(unsigned int *)(uintptr_t)(buffer_addr + EFUSE_LAYOUT_MP_FLAG_OFFSET * 4)) &
        (0x1U << EFUSE_LAYOUT_MP_FLAG_RMA_BIT_OFFSET)) {
        ret = bsp_efuse_aib_read(&value[0], EFUSE_LAYOUT_MP_FLAG_OFFSET, 2);
        if (ret) {
            tloge("fail to read efuse. ret = %d\n", ret);
            return ret;
        }
        if ((((value[0] >> EFUSE_LAYOUT_MP_FLAG_LCS_BIT_OFFSET) & 0xF) == 0x3) && value[1]) {
            tloge("set to rma mode from secure by at cmd is not allowed.\n");
            return -1;
        }
    }

    return 0;
}

int bsp_efuse_write(const unsigned int *buf, const unsigned int group, const unsigned int len)
{
    if (group < EFUSE_AIB_MAX) {
        return bsp_efuse_aib_write(buf, group, len);
    }

    return bsp_efuse_apb_write(buf, group, len);
}

int bsp_sec_efuse_write(unsigned int buffer_addr)
{
    int ret;
    unsigned int i;
    unsigned int value;
    unsigned int virt_buffer_addr = buffer_addr;

    bsp_efuse_disable_remap();

    ret = efuse_sec_group_burn(buffer_addr);
    if (ret) {
        goto error_write_otp;
    }

    ret = efuse_huk_valid_check(buffer_addr);
    if (ret) {
        goto error_write_otp;
    }

    for (i = EFUSE_LAYOUT_MP_FLAG_OFFSET; i < EFUSE_MAX_SIZE; i++) {
        value = *(unsigned int *)(uintptr_t)(virt_buffer_addr + i * 4) & efuse_write_mask[i];
        if (value) {
            ret = bsp_efuse_write(&value, i, 1);
            if (ret) {
                tloge("fail to write OTP memory, group = 0x%X ret = %d\n", i, ret);
                goto error_write_otp;
            }
        }
    }

error_write_otp:
    bsp_efuse_enable_remap();

    return ret;
}

static int bsp_dmpu_execute(unsigned int seckce_addr)
{
    int ret;
    int i;
    unsigned hbk[DX_HBK_LENGTH] = {0};
    unsigned seckce[DX_SECKCE_LENGTH] = {0};
    unsigned kce[DX_KCE_LENGTH] = {0};
    unsigned int virt_buffer_addr = seckce_addr;

    for (i = 0; i < DX_SECKCE_LENGTH; i++) {
        seckce[i] = *(unsigned int *)(uintptr_t)(virt_buffer_addr + (EFUSE_LAYOUT_KCE_OFFSET + i) * 4);
    }

    ret = SEB_CalcPublicKeyHASH(VRL_ADDR, SECBOOT_DX_WORKSPACE_ADDR, SECBOOT_DX_WORKSPACE_SIZE, hbk);
    if (ret) {
        tloge("DMPU get Hbk fail, err = 0x%x \n", ret);
        return ret;
    } else {
        tlogd("DMPU get Hbk succeed\n");
    }

    ret = SEB_DmpuUnpack(hbk, seckce, kce);
    if (ret) {
        tloge("DMPU unpack fail, err = 0x%x \n", ret);
        return ret;
    } else {
        tlogd("DMPU unpack Kce succeed\n");
    }

    for (i = 0; i < DX_KCE_LENGTH; i++) {
        g_efuse_buffer[EFUSE_LAYOUT_KCE_OFFSET + i] = kce[i];
    }

    return ret;
}

int bsp_sec_call_efuse_write_with_dmpu(unsigned int cmd, void *arg2, unsigned int arg3)
{
    int ret;
    UNUSED(cmd);
    UNUSED(arg3);

    ret = bsp_dmpu_execute((unsigned int)(uintptr_t)arg2);
    if (ret != 0) {
        return ret;
    }

    return bsp_sec_efuse_write((unsigned int)(uintptr_t)g_efuse_buffer);
}

int bsp_sec_call_efuse_write(unsigned int cmd, void *arg2, unsigned int arg3)
{
    UNUSED(cmd);
    UNUSED(arg3);

    return bsp_sec_efuse_write((unsigned int)(uintptr_t)arg2);
}

int bsp_sec_call_efuse_sec_read(unsigned int buffer_addr, const void *arg2, unsigned int arg3)
{
    UNUSED(buffer_addr);
    UNUSED(arg2);
    UNUSED(arg3);
    return 0;
}

int bsp_sec_call_efuse_sec_write(unsigned int buffer_addr, const void *arg2, unsigned int arg3)
{
    UNUSED(buffer_addr);
    UNUSED(arg2);
    UNUSED(arg3);
    return 0;
}

int bsp_sec_call_efuse_ta_read(const unsigned int group, unsigned int *buf, const unsigned int num)
{
    return bsp_efuse_apb_read(buf, group, num);
}

int bsp_efuse_aib_read(unsigned int* buf, const unsigned int group, const unsigned int len)
{
    int ret = 0;
    unsigned int i = 0;

    for (i = 0; i < len; i++) {
        ret = (int)SEB_ReadOTPWord(group+i, buf + i);
        if (ret) {
            tloge("fail to read OTP memory, group = 0x%X ret = 0x%X\n", (group+i), (unsigned int)ret);
            goto error_read_otp;
        }
    }
    tlogd("[efuse]read ret %d, ok", ret);
error_read_otp:
    return ret;
}

int bsp_efuse_aib_write(const unsigned int* buf, const unsigned int group, const unsigned int len)
{
    int ret = 0;
    unsigned int i = 0;

    for (i = 0; i < len; i++) {
        ret = (int)SEB_WriteOTPWord(group+i, *(buf + i));
        if (ret) {
            tloge("fail to write OTP memory, group = 0x%X ret = 0x%X\n", (group+i), (unsigned int)ret);
            goto error_write_otp;
        }
    }

error_write_otp:
    return ret;
}

int tee_hal_get_dieid(unsigned int *pBuffer, unsigned int u32Length)
{
    unsigned int i;
    unsigned int virt_buffer_addr;

    if (map_from_ns_page((paddr_t)(uintptr_t)pBuffer, u32Length, &virt_buffer_addr, secure)){
        tloge("map data buffer addr=0x%pK error\n", pBuffer);
        return -1;
    }

    if (u32Length < EFUSE_DIEID_SIZE) {
        tloge("fail to get dieid, length = 0x%X\n", u32Length);
        return -1;
    }

    for (i = 0; i < EFUSE_DIEID_SIZE; i++) {
        *(unsigned int*)(uintptr_t)(virt_buffer_addr+i) = g_efuse_dieid[i];
    }

    return 0;
}

unsigned SecBoot_get_secinfo_dieid(unsigned int *pBuffer)
{
    return (unsigned)tee_hal_get_dieid(pBuffer, EFUSE_DIEID_SIZE);
}

static int efuse_call_register(void)
{
    int ret;

    ret = bsp_modem_call_register(FUNC_MDRV_EFUSE_READ, (MODEM_CALL_HOOK_FUNC)bsp_sec_call_efuse_read);
    if (ret != 0) {
        tloge("FUNC_MDRV_EFUSE_READ register fail\n");
    }

    ret = bsp_modem_call_register(FUNC_MDRV_EFUSE_WRITE, (MODEM_CALL_HOOK_FUNC)bsp_sec_call_efuse_write);
    if (ret != 0) {
        tloge("FUNC_MDRV_EFUSE_WRITE register fail\n");
    }

    ret = bsp_modem_call_register(FUNC_MDRV_EFUSE_WRITE_WITH_DMPU, (MODEM_CALL_HOOK_FUNC)bsp_sec_call_efuse_write_with_dmpu);
    if (ret != 0) {
        tloge("FUNC_MDRV_EFUSE_WRITE_WITH_DMPU register fail\n");
    }

    ret = bsp_modem_call_register(FUNC_MDRV_EFUSE_SEC_READ, (MODEM_CALL_HOOK_FUNC)bsp_sec_call_efuse_sec_read);
    if (ret != 0) {
        tloge("FUNC_MDRV_EFUSE_SEC_READ register fail\n");
    }

    ret = bsp_modem_call_register(FUNC_MDRV_EFUSE_SEC_WRITE, (MODEM_CALL_HOOK_FUNC)bsp_sec_call_efuse_sec_write);
    if (ret != 0) {
        tloge("FUNC_MDRV_EFUSE_SEC_WRITE register fail\n");
    }

    ret = bsp_modem_call_register(FUNC_MDRV_EFUSE_TA_READ, (MODEM_CALL_HOOK_FUNC)bsp_sec_call_efuse_ta_read);
    if (ret != 0) {
        tloge("FUNC_MDRV_EFUSE_SEC_WRITE register fail\n");
    }

    return ret;
}

int efuse_init(void)
{
    int ret;
    unsigned int i;

    ret = efuse_call_register();
    if (ret != 0) {
        return ret;
    }

    for (i = 0; i < EFUSE_DIEID_SIZE; i++) {
        g_efuse_dieid[i] = 0;
    }

    ret = bsp_efuse_apb_read(&g_efuse_dieid[0], EFUSE_GRP_DIEID, EFUSE_DIEID_SIZE);

#if (EFUSE_DIEID_SIZE % 32)
    g_efuse_dieid[EFUSE_DIEID_SIZE-1] &= ((0x01U << (EFUSE_DIEID_SIZE%32U)) - 0x01U);
#endif
    if (ret != 0) {
        tloge("efuse init error\n");
    } else {
        tlogd("efuse init ok\n");
    }

    g_efuse_remap_status = bsp_efuse_get_remap_status();

    return ret;
}

DECLARE_TC_DRV(
        efuse_driver,
        0,
        0,
        0,
        0,
        efuse_init,
        NULL,
        NULL,
        NULL,
        NULL
        );

