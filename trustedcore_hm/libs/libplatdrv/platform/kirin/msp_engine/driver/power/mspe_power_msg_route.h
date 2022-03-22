/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declaration of power msg route.
 * Author: Security Engine
 * Create: 2020/11/07
 */
#ifndef MSPE_POWER_MSG_ROUTE_H
#define MSPE_POWER_MSG_ROUTE_H

#include <pal_types.h>

enum mspe_power_msg_type {
	MSPE_MSG_TYPE_POWER_ON_SMMU,
	MSPE_MSG_TYPE_POWER_OFF_SMMU,
	MSPE_MSG_TYPE_POWER_ON_MSPE,
	MSPE_MSG_TYPE_POWER_OFF_MSPE,
	MSPE_MSG_TYPE_POWER_DVFS,
	MSPE_MSG_TYPE_DO_NOTHING,
};

err_bsp_t mspe_power_msg_route_to_bl31(u32 cmd, u32 profile);

#endif
