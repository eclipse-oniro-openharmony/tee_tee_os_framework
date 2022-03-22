/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: klad config definition.
 * Author: Hisilicon hisecurity team
 * Create: 2019-08-12
 */

#ifndef __DRV_KLAD_CONFIG_H__
#define __DRV_KLAD_CONFIG_H__

#define KLAD_REG_RANGE             0x1000
#define KLAD_REG_BASE              (0x00b0a000 + 0xB0000000)

#define  HKL_IRQ_NUMBER            (170 + 32)
#define  HKL_IRQ_NAME              "int_hkl_tee"

#define KLAD_COM_CNT              8     /* 8 functional keyladder */
#define KLAD_TA_CNT               1     /* 1 TA keyladder, send key to functional keyladder last stage. */
#define KLAD_FPK_CNT              1     /* 1 flash protection keyladder, rootkey come from functional keyladder. */
#define KLAD_NONCE_CNT            1     /* 1 nonce keyladder, first stage input data come from functional keyladder. */
#define KLAD_CLR_CNT              1     /* 1 clear route keyladder. */

#define KLAD_MAX_SLOT_CNT        (KLAD_COM_CNT + KLAD_TA_CNT + KLAD_FPK_CNT + KLAD_NONCE_CNT + KLAD_CLR_CNT)

#endif  // __DRV_KLAD_CONFIG_H__
