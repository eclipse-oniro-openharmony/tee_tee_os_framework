/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ddr's secure protect driver of the secure os
 * Author: bujing
 * Create: 2020-09-21
 */
#include <securec.h>
#include <drv_module.h>
#include <tee_log.h>
#include <sec_region_ops.h>
#include <tzmp2_ops.h>

int ddr_sec_init(void)
{
	if (tzmp2_init()) {
		tloge("tzmp2_init failed!\n");
		return -EINVAL;
	}

	if (sec_region_init()) {
		tloge("sec_region_init failed!\n");
		return -EINVAL;
	}
	tloge("ddr_sec_drv succ!\n");
	return 0;
}

DECLARE_TC_DRV(
	ddr_sec_driver,
	0,
	0,
	0,
	TC_DRV_ARCH_INIT,
	ddr_sec_init,
	NULL,
	NULL,
	NULL,
	NULL
);
