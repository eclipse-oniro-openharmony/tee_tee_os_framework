/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu gic
 */
#include "npu_gic.h"
#include "drv_log.h"

#define DEVDRV_AICPU_CLUSTER_NAME  "aicpu_cluster"
#define DEVDRV_AICPU_CORE_NAME     "aicpu_core"
#define DEVDRV_TSCPU_CLUSTER_NAME  "tscpu_cluster"
#define DEVDRV_TSCPU_CORE_NAME     "tscpu_core"
#define DEVDRV_GIC0_SPI_BLK_NAME   "gic0_spi_blk"

int npu_plat_parse_gic(struct npu_platform_info *plat_info)
{
	(void)plat_info;
	NPU_DEBUG("aicpu cluster %d core %d, tscpu cluster %d core %d, gic0 spi blk %d \n",
		DEVDRV_PLAT_GET_AICPU_CLUSTER(plat_info),
		DEVDRV_PLAT_GET_AICPU_CORE(plat_info),
		DEVDRV_PLAT_GET_TSCPU_CLUSTER(plat_info),
		DEVDRV_PLAT_GET_TSCPU_CORE(plat_info),
		DEVDRV_PLAT_GET_GIC0_SPI_BLK(plat_info));

	return 0;
}
