/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: Library for FBE2
 * Create: 2018-06-11
 */

#ifndef _SEC_UFS_KEY_DRV_H_
#define _SEC_UFS_KEY_DRV_H_

#include <sre_typedef.h>
#include "plat_cfg.h"
#include "hisi_platform.h"
/* 16 represents CRYPTOCFG_i_0~CRYPTOCFG_i_15 */
#define CRYPTO_KEY_REG_NUM 16

/* 8*32bit from SRAM root key use decrypt DDR keys */
#define UFS_DECKEY_LEN 8

/* once decrypt 64*8 = 512bit DDR key */
#define AES_DECKEY_LEN 64

/* there are 32 groups keys */
#define MAX_CRYPTO_KEY_INDEX 32
#define MAILBOX_ID_UFS_KEY_OFFSET 9
#define UFS_REG_CRYPTOCFG_0_0 (SOC_ACPU_UFS_CFG_BASE_ADDR + 0x500)
#define UFS_REG_CRYPTOCFG_0_16 (SOC_ACPU_UFS_CFG_BASE_ADDR + 0x540)

#endif
