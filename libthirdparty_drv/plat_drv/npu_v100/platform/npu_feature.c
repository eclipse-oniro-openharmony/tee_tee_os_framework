/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu feature
 */
#include "npu_feature.h"
#include "drv_log.h"

int npu_plat_parse_feature_switch(struct npu_platform_info *plat_info)
{
	(void)plat_info;
	int i;
	for (i = 0; i < DEVDRV_FEATURE_MAX_RESOURCE; i++) {
		NPU_DEBUG("feature %d switch is %d\n", i, DEVDRV_PLAT_GET_FEAUTRE_SWITCH(plat_info, i));
	}

	return 0;
}

void npu_plat_switch_on_feature(void)
{
	struct npu_platform_info *plat_info = npu_plat_get_info();
	DEVDRV_PLAT_GET_FEAUTRE_SWITCH(plat_info, DEVDRV_FEATURE_AUTO_POWER_DOWN) = 1;
}
void npu_plat_switch_off_feature(void)
{
	struct npu_platform_info *plat_info = npu_plat_get_info();
	DEVDRV_PLAT_GET_FEAUTRE_SWITCH(plat_info, DEVDRV_FEATURE_AUTO_POWER_DOWN) = 0;
}

