/**
 * @file   : common_km.h
 * @brief  : common data provided for drv.c, hal.c, reg.c and external
 * @par    : Copyright (c) 2017-2019, HUAWEI Technology Co., Ltd.
 * @date   : 2018/01/09
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __PRIVATE_KM_H__
#define __PRIVATE_KM_H__
#include <common_sce.h>

typedef enum {
	SYMM_KEYSEL_CEK = 0,
	SYMM_KEYSEL_KDR = 1,
	SYMM_KEYSEL_GID = 2,
	SYMM_KEYSEL_RTL = 3,
	SYMM_KEYSEL_CPU = 4,
	SYMM_KEYSEL_POS = 5,
	SYMM_KEYSEL_DERIVE = 6, /* use pre derive key */
	SYMM_KEYSEL_MAX,
	SYMM_KEYSEL_UNKNOWN = SYMM_KEYSEL_MAX,
} symm_keysel_e;

#define KEYSEL_IS_CEK(keysel)       (SYMM_KEYSEL_CEK == (keysel))
#define KEYSEL_IS_KDR(keysel)       (SYMM_KEYSEL_KDR == (keysel))
#define KEYSEL_IS_GID(keysel)       (SYMM_KEYSEL_GID == (keysel))
#define KEYSEL_IS_RTL(keysel)       (SYMM_KEYSEL_RTL == (keysel))
#define KEYSEL_IS_CPU(keysel)       (SYMM_KEYSEL_CPU == (keysel))
#define KEYSEL_IS_POS(keysel)       (SYMM_KEYSEL_POS == (keysel))
#define KEYSEL_IS_DERIVE(keysel)    (SYMM_KEYSEL_DERIVE == (keysel))

#define SYMM_OUTLEN_DERIVE          BIT2BYTE(SYMM_WIDTH_128)

#endif /* end of __PRIVATE_KM_H__ */
