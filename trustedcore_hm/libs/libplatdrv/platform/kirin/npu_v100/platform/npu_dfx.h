/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu dfx
 */

#ifndef __NPU_DFX_H
#define __NPU_DFX_H

#include "npu_platform.h"

int npu_plat_parse_dfx_desc(struct npu_platform_info *plat_info, struct npu_dfx_desc *dfx_desc);

int npu_wait_tscpu_ready_status(void);
#endif
