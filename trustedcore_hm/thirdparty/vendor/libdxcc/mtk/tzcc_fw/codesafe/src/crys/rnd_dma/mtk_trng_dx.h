/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mtk hardware random generator
 * Author: heyanhong heyanhong2@huawei.com
 * Create: 2020-10-09
 */
#ifndef LIBDXCC_MTK_TRNG_H
#define LIBDXCC_MTK_TRNG_H

#include <stdint.h>

#define TRNG_BASE         0x1020F000
#define TRNG_CTRL         (TRNG_BASE + 0x0000)
#define TRNG_TIME         (TRNG_BASE + 0x0004)
#define TRNG_DATA         (TRNG_BASE + 0x0008)
#define TRNG_CONF         (TRNG_BASE + 0x000C)
#define TRNG_CTRL_RDY     0x80000000
#define TRNG_CTRL_START   0x00000001
#define TRNG_CONF_VON_EN  0x00000020

#define INFRACFG_AO_BASE  0x10001000
#define TRNG_PDN_BASE     (INFRACFG_AO_BASE)
#define TRNG_PDN_SET      (TRNG_PDN_BASE + 0x0088)
#define TRNG_PDN_CLR      (TRNG_PDN_BASE + 0x008C)
#define TRNG_PDN_STATUS   (TRNG_PDN_BASE + 0x0094)
#define TRNG_PDN_VALUE    0x200

#endif
