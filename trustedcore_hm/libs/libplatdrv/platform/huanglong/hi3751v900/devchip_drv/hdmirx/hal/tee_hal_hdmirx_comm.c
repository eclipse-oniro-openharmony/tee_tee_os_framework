/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Implementation of hdmirx functions
 * Author: Hisilicon multimedia interface software group
 * Create: 2020/01/20
 */
#include "tee_hal_hdmirx_comm.h"
#include "hi_tee_drv_os_hal.h"
#include "tee_hal_hdmirx_reg.h"

static hi_u32 g_hdcp_reg_base[HDMIRX_CTRL_CNT];
static hi_u32 g_hdcp_crg_reg_base;
static hi_u32 g_sys_ctrl_reg_base;

static hi_u32 get_right_high(hi_u32 mask)
{
    hi_u32 index;

    for (index = 0; index < 32; index++) { /* 32: check front 32 data */
        if ((mask & 0x01) == 0x01) {
            break;
        } else {
            mask >>= 1;
        }
    }
    return index;
}

static hi_u32 hdmirx_reg_read(hi_u32 addr, hi_u32 offset)
{
    hi_u32 temp;
    if (addr == 0) {
        return 0;
    }

    temp = reg_read(addr + offset);

    return temp;
}

static hi_u32 hdmirx_reg_read_fld_align(hi_u32 addr, hi_u32 offset, hi_u32 mask)
{
    hi_u32 temp;
    hi_u32 index;
    if ((mask == 0) || (addr == 0)) {
        return 0;
    }
    temp = hdmirx_reg_read(addr, offset);
    index = get_right_high(mask);
    return ((temp & mask) >> index);
}

static hi_void hdmirx_reg_read_block(hi_u32 addr, hi_u32 offset, hi_u32 *dst, hi_u32 num)
{
    if ((dst == HI_NULL) || (addr == 0)) {
        return;
    }
    while (num > 0) {
        *dst = hdmirx_reg_read(addr, offset);
        dst++;
        addr += 1;
        num--;
    }
}

static hi_void hdmirx_reg_write(hi_u32 addr, hi_u32 offset, hi_u32 value)
{
    if (addr == 0) {
        return;
    }

    reg_write(addr + offset, value);
}

static hi_void hdmirx_reg_write_block(hi_u32 addr, hi_u32 offset, hi_u32 *src, hi_u32 num)
{
    if ((src == HI_NULL) || (addr == 0)) {
        return;
    }
    while (num > 0) {
        hdmirx_reg_write(addr, offset, *src);
        src++;
        addr += 1;
        num -= 1;
    }
}

static hi_void hdmirx_reg_write_fld_align(hi_u32 addr, hi_u32 offset, hi_u32 mask, hi_u32 value)
{
    hi_u32 temp;
    hi_u32 index;

    if ((mask == 0) || (addr == 0)) {
        return;
    }

    temp = hdmirx_reg_read(addr, offset);
    index = get_right_high(mask);
    value <<= index;
    value &= mask;
    temp &= ~mask;
    temp |= value;
    hdmirx_reg_write(addr, offset, temp);
}

static hi_void hdmirx_reg_set_bits(hi_u32 addr, hi_u32 offset, hi_u32 mask, hi_bool value)
{
    hi_u32 temp;

    if ((mask == 0) || (addr == 0)) {
        return;
    }
    temp = hdmirx_reg_read(addr, offset);
    if (value == HI_TRUE) {
        temp |= (hi_u32) mask;
    } else if (value == HI_FALSE) {
        temp &= ~(hi_u32) mask;
    }
    hdmirx_reg_write(addr, offset, temp);
}

static hi_void hdmirx_hal_ctrl_reg_init(hi_void)
{
    g_hdcp_reg_base[0] = HDMIRX_PWD_REG_P0_PAD_ADDR;
    g_hdcp_reg_base[1] = HDMIRX_PWD_REG_P1_PAD_ADDR;
    g_hdcp_crg_reg_base = REG_HDMIRX_CRG_BASE_ADDR;
    g_sys_ctrl_reg_base = REG_HDMIRX_SYS_CTRL_BASE_ADDR;
}

static hi_void hdmirx_hal_ctrl_reg_deinit(hi_void)
{
    g_hdcp_reg_base[0] = HI_NULL;
    g_hdcp_reg_base[1] = HI_NULL;
    g_hdcp_crg_reg_base = HI_NULL;
    g_sys_ctrl_reg_base = HI_NULL;
}

hi_void hdmirx_hal_reg_init(hi_void)
{
    hdmirx_hal_ctrl_reg_init();
}

hi_void hdmirx_hal_reg_deinit(hi_void)
{
    hdmirx_hal_ctrl_reg_deinit();
}

hi_u32 hdmirx_hal_reg_read(hi_tee_drv_hdmirx_port port, hi_u32 addr)
{
    hi_u32 temp;

    if (port >= HDMIRX_CTRL_CNT) {
        port = HI_TEE_DRV_HDMIRX_PORT0;
    }
    temp = hdmirx_reg_read(g_hdcp_reg_base[port], addr);

    return temp;
}

hi_void hdmirx_hal_reg_write(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 value)
{
    if (port >= HDMIRX_CTRL_CNT) {
        port = HI_TEE_DRV_HDMIRX_PORT0;
    }
    hdmirx_reg_write(g_hdcp_reg_base[port], addr, value);
}

hi_u32 hdmirx_hal_reg_read_fld_align(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 mask)
{
    hi_u32 temp;

    if (port >= HDMIRX_CTRL_CNT) {
        port = HI_TEE_DRV_HDMIRX_PORT0;
    }
    temp = hdmirx_reg_read_fld_align(g_hdcp_reg_base[port], addr, mask);

    return temp;
}

hi_void hdmirx_hal_reg_write_fld_align(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 mask, hi_u32 value)
{
    if (port >= HDMIRX_CTRL_CNT) {
        port = HI_TEE_DRV_HDMIRX_PORT0;
    }
    hdmirx_reg_write_fld_align(g_hdcp_reg_base[port], addr, mask, value);
}

hi_void hdmirx_hal_reg_read_block(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 *dst, hi_u32 num)
{
    if (port >= HDMIRX_CTRL_CNT) {
        port = HI_TEE_DRV_HDMIRX_PORT0;
    }
    hdmirx_reg_read_block(g_hdcp_reg_base[port], addr, dst, num);
}

hi_void hdmirx_hal_reg_set_bits(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 mask, hi_bool value)
{
    if (port >= HDMIRX_CTRL_CNT) {
        port = HI_TEE_DRV_HDMIRX_PORT0;
    }
    hdmirx_reg_set_bits(g_hdcp_reg_base[port], addr, mask, value);
}

hi_void hdmirx_hal_reg_write_block(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 *src, hi_u32 num)
{
    if (port >= HDMIRX_CTRL_CNT) {
        port = HI_TEE_DRV_HDMIRX_PORT0;
    }
    hdmirx_reg_write_block(g_hdcp_reg_base[port], addr, src, num);
}

hi_u32 hdmirx_hal_crg_reg_read(hi_u32 offset)
{
    return hdmirx_reg_read(g_hdcp_crg_reg_base, offset);
}

hi_void hdmirx_hal_crg_write_fld_align(hi_u32 addr, hi_u32 mask, hi_u32 value)
{
    hdmirx_reg_write_fld_align(g_hdcp_crg_reg_base, addr, mask, value);
}

hi_u32 hdmirx_hal_sys_ctrl_read_fld_align(hi_u32 addr, hi_u32 mask)
{
    hi_u32 temp;

    temp = hdmirx_reg_read_fld_align(g_sys_ctrl_reg_base, addr, mask);

    return temp;
}

