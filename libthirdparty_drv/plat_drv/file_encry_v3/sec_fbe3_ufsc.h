/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ufsc driver for FBE3
 * Author: LAI Xiny
 * Create: 2020/01/07
 */

#ifndef __SEC_FBE3_UFSC_H_
#define __SEC_FBE3_UFSC_H_

#include <sre_typedef.h>
#include "soc_acpu_baseaddr_interface.h"
#include "hisi_platform.h"

/* base address for kirin hisi ufs */
#define REG_BASE_UFS_ADDR (SOC_ACPU_UFS_CFG_BASE_ADDR + 0x100000)

/* 16 represents CRYPTOCFG_i_0~CRYPTOCFG_i_15 */
#define CRYPTO_KEY_REG_NUM 16

/* once decrypt 64*8 = 512bit DDR key */
#define AES_DECKEY_LEN 64

/* there are 32 groups keys */
#define MAX_CRYPTO_KEY_INDEX 32

#define UFS_AHIT_EXIT_REQ      (REG_BASE_UFS_ADDR + 0x114)
#define UFS_AUTO_H8_STATE      (REG_BASE_UFS_ADDR + 0x130)
#define UFS_HW_PRESS_CFG       (REG_BASE_UFS_ADDR + 0x200)
#define UFS_DMA0_DFX0          (REG_BASE_UFS_ADDR + 0x288)
#define UFS_TRP_DFX1           (REG_BASE_UFS_ADDR + 0x294)
#define UFS_UTP_TX_DFX1        (REG_BASE_UFS_ADDR + 0x2B4)
#define UFS_UTP_RX_DFX2        (REG_BASE_UFS_ADDR + 0x2C8)
#define UFS_REG_CRYPTOCFG_0_0  (REG_BASE_UFS_ADDR + 0x500)
#define UFS_REG_CRYPTOCFG_0_16 (REG_BASE_UFS_ADDR + 0x540)
#define UFS_REG_KEY_KDF_EN     (REG_BASE_UFS_ADDR + 0x03AC)
#define UFS_CORE_UTRLRSR(n)    (REG_BASE_UFS_ADDR + 0x201C + (n)*0x80)

#define UFS_CORE_NUM 8
#define AHIT_EXIT_REQ 1
#define UFS_UTP_PRESS 0x3
#define UNIIF_IDLE_STATE 0x1
#define UTP_FIFO_FULL (1 << 14)
/* UFS_DMA0_DFX0 */
#define TRP_DMA0_RD_UTRD_REQ (1 << 5)
#define TRP_DMA0_RD_CMD_REQ (1 << 6)
#define DMA0_RD_CMDQ_EMPTY (1 << 8)

#define cmd_state(val) (((val) >> 8) & 0x7)
#define dma0_read_is_empty(val)                                                   \
	(((val) & TRP_DMA0_RD_UTRD_REQ) == 0 &&                                  \
	 ((val) & TRP_DMA0_RD_CMD_REQ) == 0 && ((val) & DMA0_RD_CMDQ_EMPTY))

#define utp_tx_outstanding(val) ((val >> 22) & 0xF)
#define utp_rx_fsm(val) (val & 0xFF)
#define auto_h8_state(val) ((val) & 0xFF)
#define AH8_XFER 1
#define AH8_IDLE 2

#define UFS_DATA_STOP 0
#define UFS_DATA_START 1
#define UFS_RETRY_MAX 100 /* unit 100us */
#define UFS_AH8_RETRY_MAX 50 /* unit: ms */

UINT32 file_encry_config_ufsc(UINT32 ufs_slot, UINT8 *key, UINT32 length);
UINT32 file_encry_enable_kdf(void);

#endif
