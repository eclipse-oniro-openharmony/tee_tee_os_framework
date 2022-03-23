/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2020. All rights reserved.
 * Description: tzpc configure
 * Author: security-ap
 * Create: 2013-06-01
 */

#ifndef __TZPC_CFG_H__
#define __TZPC_CFG_H__

#include "tzpc_plat.h"
#include <tzpc.h>
#include <sre_typedef.h>

#define INVALID_ID  (-1)

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#include "./cfg/tzpc_cfg_miami.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW)
#include "./cfg/tzpc_cfg_miamicw.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
#include "./cfg/tzpc_cfg_kirin970.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
#include "./cfg/tzpc_cfg_kirin980.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#if defined(WITH_KIRIN990_CS)
#include "./cfg/tzpc_cfg_kirin990.h"
#else
#include "./cfg/tzpc_cfg_kirin990cs2.h"
#endif

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#include "./cfg/tzpc_cfg_orlando.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#include "./cfg/tzpc_cfg_baltimore.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#include "./cfg/tzpc_cfg_denver.h"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_LAGUNA)
#include "./cfg/tzpc_cfg_laguna.h"
#endif
#endif /* __TZPC_CFG_H__ */
