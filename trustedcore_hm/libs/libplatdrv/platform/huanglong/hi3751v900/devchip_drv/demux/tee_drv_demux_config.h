/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: demux tee configuration file.
 * Author: sdk
 * Create: 2019-06-05
 */

#ifndef __TEE_DRV_DEMUX_CONFIG_H__
#define __TEE_DRV_DEMUX_CONFIG_H__

#if defined(CHIP_TYPE_hi3796cv300) || defined(CHIP_TYPE_hi3751v900)

#define DMX_REGS_BASE                   0x00C00000
#define DMX_REGS_SWH_BASE               0x04000
#define DMX_REGS_FLT_BASE               0x0A000
#define DMX_REGS_SCD_BASE               0x0C000
#define DMX_REGS_CFG_BASE               0x0E000
#define DMX_REGS_PAR_BASE               0x10000
#define DMX_REGS_DAV_BASE               0x20000

#define DMX_REGS_MDSC_BASE              0x00BEC000
#define DMX_IRQ_NUMBER                 (174 + 32)
#define DMX_IRQ_NAME                   "int_dmx"

#define DMX_CNT                         16
#define DMX_RAMPORT_CNT                 16
#define DMX_PLAY_TS_CNT                 96
#define DMX_PLAY_SEC_PES_CNT            96
#define DMX_AVR_CNT                     64  /* audio video record */
#define DMX_SCD_CNT                     256
#define DMX_PID_COPY_CNT                32

#define DMX_KEY_CNT                     256

#define DMX_RAW_PIDCH_CNT               1024
#define DMX_BUF_CNT                     512

#define DMX_MAX_SEC_LEN                 0x1000

#endif

#endif      /* __TEE_DRV_DEMUX_CONFIG_H__ */
