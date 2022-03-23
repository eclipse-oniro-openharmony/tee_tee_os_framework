/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2011-2020. All rights reserved.
 * Description: tzpc common configure
 * Create: 2011-06-01
 */

#ifndef __TZPC_H__
#define __TZPC_H__

#if (TRUSTEDCORE_PLATFORM_CHOOSE == WITH_HIGENERIC_PLATFORM)
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#include "tzpc_miami.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW)
#include "tzpc_miamicw.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
#include "tzpc_kirin970.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
#include "tzpc_kirin980.h"


#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#if defined(WITH_KIRIN990_CS)
#include "tzpc_kirin990.h"
#else
#include "tzpc_kirin990cs2.h"
#endif

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#include "tzpc_orlando.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#include "tzpc_baltimore.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#include "tzpc_denver.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_LAGUNA)
#include "tzpc_laguna.h"
#endif
#endif

enum {
	TZPC_SEC = 0,
	TZPC_UNSEC,
	/* u can add here */
	TZPC_ATTR_MAX
};

int tzpc_cfg(unsigned int ip_num, unsigned int sec_status);
int tzpc_get(unsigned int ip_num);
#endif /* __TZPC_H__ */
