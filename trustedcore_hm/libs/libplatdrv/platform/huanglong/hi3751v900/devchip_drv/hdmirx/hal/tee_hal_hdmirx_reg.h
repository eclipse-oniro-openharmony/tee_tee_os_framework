/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definitions of registers
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-01-20
 */
#ifndef __TEE_HAL_HDMIRX_REG_H__
#define __TEE_HAL_HDMIRX_REG_H__

#include "tee_hal_hdmirx_product.h"

#define REG_HDMIRX_SYS_CTRL_BASE_ADDR 0x00840000
#define REG_HDMIRX_CRG_BASE_ADDR      0x00a0047c

#define REG_SYS_LICENSE_SUPPORT 0x1434
#define HDMIRX_LICENSE_SUPPORT  0x10 /* 1: support, 0: not support */

#define REG_PERI_CRG_287 0x00
#define HDMIRX_2P0_PWD_APB_SRST_REQ    0x01 /* mask bit 0 */
#define HDMIRX_2P0_PWD_SRST_REQ        0x02 /* mask bit 1 */
#define HDMIRX_2P0_PWD_APB_CKEN        0x04 /* mask bit 2 */
#define HDMIRX_2P0_PWD_MEDIA_CFG_CKEN  0x08 /* mask bit 3 */
#define HDMIRX_2P0_PWD_MEDIA_CKEN      0x10 /* mask bit 4 */
#define HDMIRX_2P0_PWD_LINK_CFG_CKEN   0x20 /* mask bit 5 */
#define HDMIRX_2P0_PWD_LINK_CKEN       0x40 /* mask bit 6 */
#define HDMIRX_2P0_PWD_TEST_PHYREF_CLK_DIV 0x180 /* mask bit 8:7 */
#define HDMIRX_2P0_PWD_TEST_PHYREF_CKEN 0x200 /* mask bit 9 */
#define HDMIRX_2P0_AON_APB_SRST_REQ    0x400 /* mask bit 10 */
#define HDMIRX_2P0_AON_SRST_REQ        0x800 /* mask bit 11 */
#define HDMIRX_2P0_AON_CKEN            0x1000 /* mask bit 12 */
#define HDMIRX_PHY_REF_CKSEL           0x2000 /* mask bit 13 */
#define HDMIRX_VI_INTF_CKEN            0x4000 /* mask bit 14 */
#define HDMIRX_DSCD_CKEN               0x8000 /* mask bit 15 */
#define HDMIRX_LINK_CKEN               0x10000 /* mask bit 16 */
#define HDMIRX_MEDIA_CKEN              0x20000 /* mask bit 17 */

#define REG_PERI_CRG_288 0x04
#define HDMIRX_2P1_PWD_APB_SRST_REQ    0x01
#define HDMIRX_2P1_PWD_SRST_REQ        0x02
#define HDMIRX_2P1_PWD_APB_CKEN        0x04
#define HDMIRX_2P1_PWD_MEDIA_CFG_CKEN  0x08
#define HDMIRX_2P1_PWD_MEDIA_CKEN      0x10
#define HDMIRX_2P1_PWD_LINK_CFG_CKEN   0x20
#define HDMIRX_2P1_PWD_LINK_CKEN       0x40
#define HDMIRX_2P1_PWD_TEST_PHYREF_CLK_DIV 0x180
#define HDMIRX_2P1_PWD_TEST_PHYREF_CKEN 0x200
#define HDMIRX_DSCD_SRST_REQ            0x2000 /* mask bit 13 */

#define REG_RX_PWD_STATUS 0x1C
#define PWD_STAT_HDCP_DET_STAT 0x20 /* mask bit 5 */

#define REG_RX_PWD_SRST 0x20
#define CFG_HDCPD_SRST_REQ             0x1000000  /* mask bit 24 */
#define CFG_HDCP1X_CIPHER_SRST_REQ     0x2000000  /* mask bit 25 */
#define CFG_HDCP1X_SRST_REQ            0x4000000  /* mask bit 26 */
#define CFG_HDCP1X_KEYOP_SRST_REQ      0x8000000  /* mask bit 27 */
#define CFG_HDCP2X_SRST_REQ            0x10000000 /* mask bit 28 */
#define CFG_HDCP2X_AUTH_SRST_REQ       0x20000000 /* mask bit 29 */
#define CFG_HDCP2X_CYP_SRST_REQ        0x40000000 /* mask bit 30 */
#define CFG_HDCP2X_MCU_SRST_REQ        0x80000000 /* mask bit 31 */

#define REG_HDMIRX_HDCP2X_PRAME (HDMIRX_HDCP2X_MCU_PRAME_BASE + 0x00)
#define REG_HDMIRX_HDCP2X_DRAME (HDMIRX_HDCP2X_MCU_DRAME_BASE + 0x00)

/* HDCP2X Ctrl register */
#define REG_HDCP2X_KEY_BIST_CTRL (HDMIRX_HDCP2X_CTRL_BASE + 0x8)
#define CPU_LOAD_RCV_ID_EN   0x1 /* mask bit 0 */
#define CPU_KEY_RAM_CRC_EN   0x2 /* mask bit 1 */
#define CPU_PRIVKEY_CKSUM_EN 0x4 /* mask bit 2 */

#define REG_HDCP2X_KEY_BIST_STA (HDMIRX_HDCP2X_CTRL_BASE + 0xC)
#define KEY_RAM_BIST_BUSY   0x1  /* mask bit 0 */
#define LOAD_RCV_ID_READY   0x2  /* mask bit 1 */
#define KEY_RAM_CRC_READY   0x4  /* mask bit 2 */
#define KEY_RAM_CRC_PASS    0x8  /* mask bit 3 */
#define PRIVKEY_CKSUM_READY 0x10 /* mask bit 4 */
#define PRIVKEY_CKSUM_PASS  0x20 /* mask bit 5 */

#define REG_HDCP2X_RCV_ID_LSB (HDMIRX_HDCP2X_CTRL_BASE + 0x18)
#define HDCP2X_RCV_ID_LSB 0xFFFFFFFF /* mask bit 31:0 */

#define REG_HDCP2X_RCV_ID_MSB (HDMIRX_HDCP2X_CTRL_BASE + 0x1C)
#define HDCP2X_RCV_ID_MSB 0xFF /* mask bit 7:0 */

#define REG_HDCP2X_SEC_INTR_B0 (HDMIRX_HDCP2X_CTRL_BASE + 0x840)
#define HDCP2X_SEC_INTR0 0x1  /* mask bit 0 content stream type changed */

#define REG_HDCP2X_SEC_MASK_B0 (HDMIRX_HDCP2X_CTRL_BASE + 0x848)
#define HDCP2X_SEC_MASK0 0x1  /* mask bit 0 */

#define REG_HDCP2X_CPU_INTR_B0 (HDMIRX_HDCP2X_CTRL_BASE + 0x8B0)
#define HDCP2X_CPU_INTR0 0x1  /* mask bit 0 repeater change */
#define HDCP2X_CPU_INTR1 0x2  /* mask bit 1 rcvid list ready */
#define HDCP2X_CPU_INTR2 0x4  /* mask bit 2 reauth req */

#define REG_HDCP2X_GEN_OUT13 (HDMIRX_HDCP2X_CTRL_BASE + 0x9B4)
#define HDCP2X_MCU_STATUS 0xF /* 0-none, 1-authing, 2-success, 3-failed */

#define REG_HDCP2X_SEC_IN0 (HDMIRX_HDCP2X_CTRL_BASE + 0xA40)
#define HDCP1X_DEVICE_DOWNSTREAM   0x1  /* mask bit 0 */
#define HDCP2X_REPEATER_DOWNSTREAM 0x2  /* mask bit 1 */
#define HDCP_MAX_CASCADE_EXCEEDED  0x4  /* mask bit 2 */
#define HDCP_MAX_DEVS_EXCEEDED     0x8  /* mask bit 3 */
#define HDCP2X_REPEATER_MODE       0x10 /* mask bit 4 */

#define REG_HDCP2X_SEC_IN1 (HDMIRX_HDCP2X_CTRL_BASE + 0xA44)
#define HDCP_DEVICE_COUNT 0x1F /* mask bit 4:0 */
#define HDCP_DEPTH        0xE0 /* mask bit 7:5 */

#define REG_HDCP2X_SEC_OUT0 (HDMIRX_HDCP2X_CTRL_BASE + 0xA60)
#define CONTENT_STREAM_TYPE 0x1 /* mask bit 0 */

#define REG_CFG_AUTH_STATE (HDMIRX_HDCP14_CTRL_BASE + 0x4C)
#define CFG_AUTH_DONE  0x1  /* mask bit 0 */
#define CFG_CURR_STATE 0xF0 /* mask bit 7:4 */

#define REG_CFG_RPT_BSTATUS (HDMIRX_HDCP14_CTRL_BASE + 0x124)
#define CFG_DEVICE_COUNT         0x7F   /* mask bit 6:0 */
#define CFG_MAX_DEVS_EXCEEDED    0x80   /* mask bit 7 */
#define CFG_DEPTH                0x700  /* mask bit 10:8 */
#define CFG_MAX_CASCADE_EXCEEDED 0x800  /* mask bit 11 */

#define REG_CFG_RPT_SHA_CTRL (HDMIRX_HDCP14_CTRL_BASE + 0x128)
#define CFG_SHA_START 0x1 /* mask bit 0 */

#define REG_CFG_RPT_CAP (HDMIRX_HDCP14_CTRL_BASE + 0x130)
#define CFG_RPT_CAP 0x1  /* mask bit 0 */

#define REG_HDCP1X_KSV_FIFO (HDMIRX_HDCP14_CTRL_BASE + 0xC00)

#endif

