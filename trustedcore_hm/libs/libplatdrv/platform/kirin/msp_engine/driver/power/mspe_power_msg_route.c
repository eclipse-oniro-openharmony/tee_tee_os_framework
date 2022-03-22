/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp power msg route to bl31
 * Author: Security Engine
 * Create: 2020/11/04
 */
#include "mspe_power_msg_route.h"
#include <pal_errno.h>
#include <pal_log.h>
#include <common_utils.h>
#include <hieps_errno.h>
#include <hieps_smc.h>

#define BSP_THIS_MODULE BSP_MODULE_POWER

err_bsp_t mspe_power_msg_route_to_bl31(u32 cmd, u32 profile)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);
	u32 power_cmd = HIEPS_POWER_DEFAULT_CMD;
	u32 tcu_cmd = HIEPS_TCU_POWER_DEFAULT_CMD;

	switch (cmd) {
	case MSPE_MSG_TYPE_POWER_ON_SMMU:
		tcu_cmd = HIEPS_TCU_POWER_ON_CMD;
		break;
	case MSPE_MSG_TYPE_POWER_OFF_SMMU:
		tcu_cmd = HIEPS_TCU_POWER_OFF_CMD;
		break;
	case MSPE_MSG_TYPE_POWER_ON_MSPE:
		power_cmd = HIEPS_POWER_ON_CMD;
		break;
	case MSPE_MSG_TYPE_POWER_OFF_MSPE:
		power_cmd = HIEPS_POWER_OFF_CMD;
		break;
	case MSPE_MSG_TYPE_POWER_DVFS:
		power_cmd = HIEPS_DVFS_CMD;
	default:
		return BSP_RET_OK;
	}

	/*
	* arg0: cmd: HIEPS_POWER_ON_CMD
	*            HIEPS_POWER_OFF_CMD
	*            HIEPS_DVFS_CMD
	* arg1: profile
	* arg2: tcu_cmd:
	*            HIEPS_TCU_POWER_ON_CMD
	*            HIEPS_TCU_POWER_OFF_CMD
	* arg3: not used
	*/
	ret = hieps_smc_send_process(power_cmd, profile, tcu_cmd, 0);
	if (PAL_CHECK(ret != HIEPS_OK)) {
		PAL_ERROR("hieps_smc_send_process fail, ret=%x\n", ret);
		ret = ERR_DRV(ERRCODE_REQUEST);
	}

	return (ret == HIEPS_OK) ? BSP_RET_OK : ret;
}
