/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HDCP DPTX AUX DPCD Driver
 * Author: Hisilicon DSS
 * Create: 2019-07-07
 */

#ifndef HISI_HDCP_DP_H
#define HISI_HDCP_DP_H

#include "hisi_hdcp_common.h"

#define UINT8_WIDTH_IN_BITS 8

#define AUX_DATA_REG_CNT    4
#define DPCD_READ_CNT       16
#define DPTX_WAIT_REPLY_CNT 5000
#define DPTX_RW_WAIT_CNT    1000
#define DPTX_RW_RETRY_CNT   100

#define DATA_INDEX0 0
#define DATA_INDEX1 1
#define DATA_INDEX2 2
#define DATA_INDEX3 3

#define DPTX_RW_RETRY   1
#define DPTX_RW_SUCCESS 0
#define DPTX_RW_ERR     (-1)

// DPTX registers
#define DPTX_AUX_CMD_ADDR 0x0050

#define DPTX_AUX_REQ     0x0074
#define DPTX_CFG_AUX_REQ 1u

#define DPTX_AUX_WR_DATA0 0x0054
#define DPTX_AUX_WR_DATA1 0x0058
#define DPTX_AUX_WR_DATA2 0x005C
#define DPTX_AUX_WR_DATA3 0x0060

#define DPTX_AUX_RD_DATA0 0x0064
#define DPTX_AUX_RD_DATA1 0x0068
#define DPTX_AUX_RD_DATA2 0x006C
#define DPTX_AUX_RD_DATA3 0x0070

#define DPTX_AUX_CMD_REQ_LEN_SHIFT  0
#define DPTX_AUX_CMD_ADDR_SHIFT     8
#define DPTX_AUX_CMD_TYPE_SHIFT     28
#define DPTX_AUX_CMD_TYPE_WRITE     0x0
#define DPTX_AUX_CMD_TYPE_READ      0x1
#define DPTX_AUX_CMD_TYPE_NATIVE    0x8

#define DPTX_AUX_STATUS                       0x0078
#define DPTX_CFG_AUX_STATUS_MASK              0x0FF0 /* bit4-bit11 */
#define DPTX_CFG_AUX_STATUS_SHIFT             4
#define DPTX_CFG_AUX_REPLY_ERR_DETECTED_MASK  0x0E /* bit1-bit3 */
#define DPTX_CFG_AUX_REPLY_ERR_DETECTED_SHIFT 1
#define DPTX_CFG_AUX_TIMEOUT                  1u /* bit0 */
#define DPTX_CFG_AUX_READY_BYTE_MASK          0x01F000 /* bit12-bit16 */
#define DPTX_CFG_AUX_READY_BYTE_SHIFT         12

#define DPTX_CFG_AUX_STATUS_ACK       0x0
#define DPTX_CFG_AUX_STATUS_AUX_NACK  0x10
#define DPTX_CFG_AUX_STATUS_I2C_NACK  0x40
#define DPTX_CFG_AUX_STATUS_AUX_DEFER 0x20
#define DPTX_CFG_AUX_STATUS_I2C_DEFER 0x80

int dptx_read_bytes_from_dpcd(uint32_t regAddr, uint8_t *bytes, uint32_t len);
int dptx_write_bytes_to_dpcd(uint32_t regAddr, uint8_t *bytes, uint32_t len);

#endif
