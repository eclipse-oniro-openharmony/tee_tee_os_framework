/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2020. All rights reserved.
 * Description: tzpc plat data
 * Create: 2013-06-01
 */

#ifndef __TZPC_PLAT_H__
#define __TZPC_PLAT_H__
#include <soc_acpu_baseaddr_interface.h>

#define REG_BASE_TZPC           SOC_ACPU_TZPC_BASE_ADDR
#define REG_BASE_AO_TZPC        SOC_ACPU_AO_TZPC_BASE_ADDR

#define TZPC_MAX_UNIT           9
#define TZPC_BASE_ADDR          REG_BASE_TZPC
#define TZPC_AO_BASE_ADDR       REG_BASE_AO_TZPC

typedef struct {
	unsigned int ip_idx;
	unsigned char tbl_no;
	unsigned char unit_no;
	unsigned char bit_no;
	unsigned char def_status;
} TZPC_BIT_DEF;

enum {
	TZPC_TABLE_PERI = 0,
	TZPC_TABLE_AO = 1,
	/* u can add here */
	TZPC_TABLE_MAX
};


#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#include "./plat/tzpc_plat_miami.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW)
#include "./plat/tzpc_plat_miamicw.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
#include "./plat/tzpc_plat_kirin970.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
#include "./plat/tzpc_plat_kirin980.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#if defined(WITH_KIRIN990_CS2)
#include "./plat/tzpc_plat_kirin990cs2.h"
#else
#include "./plat/tzpc_plat_kirin990.h"
#endif

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#include "./plat/tzpc_plat_orlando.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#include "./plat/tzpc_plat_baltimore.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#include "./plat/tzpc_plat_denver.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_LAGUNA)
#include "./plat/tzpc_plat_laguna.h"
#endif
#endif /* __TZPC_PLAT_H__ */
