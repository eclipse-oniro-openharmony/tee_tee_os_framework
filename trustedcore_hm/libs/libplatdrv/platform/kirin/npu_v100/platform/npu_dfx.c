/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu dfx
 */
#include "npu_dfx.h"
#include "drv_log.h"
#include "npu_resmem.h"
#include "npu_platform.h"
#include "npu_platform_register.h"

#define DEVDRV_DFX_CHANNEL_NAME "channel"
#define DEVDRV_DFX_RESMEM_NAME  "buf_idx"

int npu_plat_parse_dfx_desc(struct npu_platform_info *plat_info, struct npu_dfx_desc *dfx_desc)
{
	(void)plat_info;
	(void)dfx_desc;
	return 0;
}

