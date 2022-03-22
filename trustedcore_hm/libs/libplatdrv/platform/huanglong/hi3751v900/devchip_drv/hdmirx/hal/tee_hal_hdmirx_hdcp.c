/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Implementation of hdcp functions
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-01-20
 */
#include "tee_hal_hdmirx_hdcp.h"
#include "tee_hal_hdmirx_comm.h"
#include "tee_hal_hdmirx_reg.h"
#include "tee_drv_hdmirx_comm.h"
#include "hi_tee_drv_os_hal.h"

#define MCU_PRAM_SIZE  8192 /* 32KB/4 = 8192 word */

#define HDCP_BKSV_OR_RECV_ID_LEN    5
#define HDMIRX_HDCP_KSV_LIST_MAX    127
#define HDMIRX_HDCP_RECVID_LIST_MAX 31
#define HDMIRX_HDCP_KSV_SIZE        5

hi_void tee_hal_hdmirx_hdcp14_set_rpt_bcaps(hi_tee_drv_hdmirx_port port, hi_bool repeater)
{
    hdmirx_hal_reg_write_fld_align(port, REG_CFG_RPT_CAP, CFG_RPT_CAP, repeater);
}

hi_void tee_hal_hdmirx_hdcp14_set_rpt_bstatus(hi_tee_drv_hdmirx_port port, const tee_hdmirx_hdcp14_bstatus *bstatus)
{
    hi_u32 value = 0;

    value |= (bstatus->device_count & CFG_DEVICE_COUNT);
    value |= ((bstatus->max_devs_exceeded << 7) & CFG_MAX_DEVS_EXCEEDED); /* 7: bit7 */
    value |= ((bstatus->depth << 8) & CFG_DEPTH); /* 8: bit[10:8] */
    value |= ((bstatus->max_cascade_exceeded << 11) & CFG_MAX_CASCADE_EXCEEDED); /* 11: bit11 */

    hi_log_info("depth %d\n", bstatus->depth);
    hi_log_info("device_count %d\n", bstatus->device_count);
    hi_log_info("max_devs_exceeded %d\n", bstatus->max_devs_exceeded);
    hi_log_info("max_cascade_exceeded %d\n", bstatus->max_cascade_exceeded);

    hdmirx_hal_reg_write_fld_align(port, REG_CFG_RPT_BSTATUS, 0xFFF, value);
}

hi_u32 tee_hal_hdmirx_hdcp14_set_rpt_bksv_list(hi_tee_drv_hdmirx_port port, const hi_u8 *bksv_list, hi_u8 len)
{
    hi_u32 max_len = HDMIRX_HDCP_KSV_LIST_MAX * HDMIRX_HDCP_KSV_SIZE;
    hi_u32 addr = REG_HDCP1X_KSV_FIFO;
    hi_u32 i, j, remainder;
    hi_u32 value;

    max_len = (len > max_len) ? max_len : len;
    remainder = len % 4; /* 4: one register has 4 bytes */

    for (i = 0; i < max_len - 3; i += 4, addr += 4) { /* 3: offset 3 byte; 4: one register has 4 bytes */
        value  = bksv_list[i];
        value |= bksv_list[i + 1] << 8;  /* 8: bit[15:8] */
        value |= bksv_list[i + 2] << 16; /* 16: bit[23:16] */
        value |= bksv_list[i + 3] << 24; /* 24: bit[31:24] */
        hdmirx_hal_reg_write(port, addr, value);
    }

    value = 0;
    for (j = 0; j < remainder; j++) {
        value |= bksv_list[i + j] << (j * 8); /* 8: one byte consists of 8 bits. */
    }
    hdmirx_hal_reg_write(port, addr, value);

    return len;
}

hi_void tee_hal_hdmirx_hdcp14_start_rpt_sha1(hi_tee_drv_hdmirx_port port)
{
    hdmirx_hal_reg_write_fld_align(port, REG_CFG_RPT_SHA_CTRL, CFG_SHA_START, HI_TRUE);
}

hi_s32 tee_hal_hdmirx_hdcp_load_mcu(hi_tee_drv_hdmirx_port port, const hi_u32 *pram, hi_u32 max_len)
{
    hi_u32 num, addr;

    if (max_len > MCU_PRAM_SIZE) {
        return HI_FAILURE;
    }

    /* reset mcu first */
    hdmirx_hal_reg_write_fld_align(port, REG_RX_PWD_SRST, CFG_HDCP2X_MCU_SRST_REQ, HI_TRUE);

    /* write mcu data to pram */
    for (num = 0; num < max_len; num++) {
        addr = num * 4; /* 4 : 1 reg = 4 byte */
        hdmirx_hal_reg_write(port, addr + REG_HDMIRX_HDCP2X_PRAME, pram[num]);
    }
    /* write 0 to another free pram */
    for (; num < MCU_PRAM_SIZE; num++) {
        addr = num * 4; /* 4 : 1 reg = 4 byte */
        hdmirx_hal_reg_write(port, addr + REG_HDMIRX_HDCP2X_PRAME, 0);
    }

    return HI_SUCCESS;
}

hi_s32 tee_hal_hdmirx_hdcp_check_mcu_code(hi_tee_drv_hdmirx_port port, const hi_u32 *pram, hi_u32 max_len)
{
    hi_u32 len = MCU_PRAM_SIZE;
    hi_u32 num, addr, pram_data;
    hi_s32 ret = HI_SUCCESS;

    if (max_len < MCU_PRAM_SIZE) {
        len = max_len;
    }

    for (num = 0; num < len; num++) {
        addr = num * 4; /* 4 : 1 reg = 4 byte */
        pram_data = hdmirx_hal_reg_read(port, addr + REG_HDMIRX_HDCP2X_PRAME);
        if (pram_data != pram[num]) {
            hi_log_err("tee pram data err: num(%u), reg:0x%x-0x%x\n", num, pram_data, pram[num]);
            ret = HI_FAILURE;
            break;
        }
    }

    return ret;
}

hi_void tee_hal_hdmirx_hdcp2x_set_rpt_rxcaps(hi_tee_drv_hdmirx_port port, hi_bool repeater)
{
    hdmirx_hal_reg_write_fld_align(port, REG_HDCP2X_SEC_IN0, HDCP2X_REPEATER_MODE, repeater);
}

hi_void tee_hal_hdmirx_hdcp2x_set_rpt_irq(hi_tee_drv_hdmirx_port port, tee_hdmirx_hdcp2x_irq irq)
{
    switch (irq) {
        case TEE_HDMIRX_HDCP2X_REPEATER_CHANGE:
            hdmirx_hal_reg_write_fld_align(port, REG_HDCP2X_CPU_INTR_B0, HDCP2X_CPU_INTR0, HI_TRUE);
            break;
        case TEE_HDMIRX_HDCP2X_RCVID_LIST_READY:
            hdmirx_hal_reg_write_fld_align(port, REG_HDCP2X_CPU_INTR_B0, HDCP2X_CPU_INTR1, HI_TRUE);
            break;
        case TEE_HDMIRX_HDCP2X_RE_AUTH:
            hdmirx_hal_reg_write_fld_align(port, REG_HDCP2X_CPU_INTR_B0, HDCP2X_CPU_INTR2, HI_TRUE);
            break;
        default:
            break;
    }
}

hi_void tee_hal_hdmirx_hdcp2x_set_rpt_rxinfo(hi_tee_drv_hdmirx_port port, const tee_hdmirx_hdcp2x_rxinfo *rxinfo)
{
    hi_u32 value_in1 = 0;
    hi_u32 value_in0 = 0;

    value_in1 |= ((rxinfo->depth << 5) & HDCP_DEPTH); /* 5: bit[7:5] */
    value_in1 |= (rxinfo->device_count & HDCP_DEVICE_COUNT);

    hdmirx_hal_reg_write_fld_align(port, REG_HDCP2X_SEC_IN1, BIT7_0, value_in1);

    value_in0 |= (rxinfo->hdcp1_device_downstream & HDCP1X_DEVICE_DOWNSTREAM);
    value_in0 |= ((rxinfo->hdcp2_0_repeater_downstream << 1) & HDCP2X_REPEATER_DOWNSTREAM);
    value_in0 |= ((rxinfo->max_cascade_exceeded << 2) & HDCP_MAX_CASCADE_EXCEEDED); /* 2: bit[2] */
    value_in0 |= ((rxinfo->max_devs_exceeded << 3) & HDCP_MAX_DEVS_EXCEEDED); /* 3: bit[3] */

    hdmirx_hal_reg_write_fld_align(port, REG_HDCP2X_SEC_IN0, BIT3_0, value_in0);
}

hi_u32 tee_hal_hdmirx_hdcp2x_set_rpt_rcvid_list(hi_tee_drv_hdmirx_port port, const hi_u8 *rcvid_list, hi_u8 len)
{
    hi_u32 max_len = HDMIRX_HDCP_RECVID_LIST_MAX * HDCP_BKSV_OR_RECV_ID_LEN;
    hi_u32 cnt, addr;
    hi_u32 *list = (hi_u32 *)rcvid_list;

    max_len = (len > max_len) ? max_len : len;

    hi_log_info("max_len = %d\n", max_len);

    for (cnt = 0; cnt < max_len; cnt++) {
        addr = cnt * 4; /* 4: one register has 4 bytes */
        hdmirx_hal_reg_write(port, addr + HDMIRX_HDCP2X_MCU_DRAME_BASE, *(list + cnt));
    }

    return cnt;
}

hi_void tee_hal_hdmirx_streamtype_irq_en(hi_tee_drv_hdmirx_port port, hi_bool en)
{
    hdmirx_hal_reg_write_fld_align(port, REG_HDCP2X_SEC_MASK_B0, HDCP2X_SEC_MASK0, en);
}

hi_void tee_hal_hdmirx_streamtype_intr_clear(hi_tee_drv_hdmirx_port port)
{
    hdmirx_hal_reg_write_fld_align(port, REG_HDCP2X_SEC_INTR_B0, HDCP2X_SEC_INTR0, 1);
}

hi_u32 tee_hal_hdmirx_streamtype_get(hi_tee_drv_hdmirx_port port)
{
    return hdmirx_hal_reg_read_fld_align(port, REG_HDCP2X_SEC_OUT0, CONTENT_STREAM_TYPE);
}

tee_hdmirx_hdcp_auth_status tee_hal_hdcp_get_auth_status(hi_tee_drv_hdmirx_port port,
    hi_tee_drv_hdmirx_hdcp_type hdcp_type)
{
    tee_hdmirx_hdcp_auth_status status = TEE_HDCP_AUTH_NONE;

    if (hdcp_type == HI_TEE_DRV_HDMIRX_HDCPTYPE_22) {
        status = hdmirx_hal_reg_read_fld_align(port, REG_HDCP2X_GEN_OUT13, HDCP2X_MCU_STATUS);
    } else if (hdcp_type == HI_TEE_DRV_HDMIRX_HDCPTYPE_14) {
        status = hdmirx_hal_reg_read_fld_align(port, REG_CFG_AUTH_STATE, CFG_AUTH_DONE);
        status = (status > 0) ? TEE_HDCP_AUTH_SUCCESS : TEE_HDCP_AUTH_FAILED;
    }

    if (status >= TEE_HDCP_AUTH_MAX) {
        status = TEE_HDCP_AUTH_NONE;
    }

    return status;
}

hi_tee_drv_hdmirx_hdcp_type tee_hal_hdcp_check_type(hi_tee_drv_hdmirx_port port)
{
    hi_u32 type, hdcp1x_auth_state;
    tee_hdmirx_hdcp_auth_status hdcp2x_auth_status;

    type = hdmirx_hal_reg_read_fld_align(port, REG_RX_PWD_STATUS, PWD_STAT_HDCP_DET_STAT);
    hdcp1x_auth_state = hdmirx_hal_reg_read_fld_align(port, REG_CFG_AUTH_STATE, CFG_CURR_STATE);
    hdcp2x_auth_status = tee_hal_hdcp_get_auth_status(port, HI_TEE_DRV_HDMIRX_HDCPTYPE_22);
    if (type == HI_TRUE && hdcp2x_auth_status != TEE_HDCP_AUTH_NONE) {
        return HI_TEE_DRV_HDMIRX_HDCPTYPE_22;
    }
    if ((hdcp1x_auth_state == 0) || (hdcp1x_auth_state == 0x2)) { /* 0x2 : authenticate first step */
        return HI_TEE_DRV_HDMIRX_HDCPTYPE_UNKNOWN;
    }
    return HI_TEE_DRV_HDMIRX_HDCPTYPE_14;
}

