/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2020. All rights reserved.
 * Description: ssm export function defines
 * Author: hisilicon
 * Create: 2020-01-10
 */

#ifndef __HI_TEE_DRV_SSM_H__
#define __HI_TEE_DRV_SSM_H__

#include "hi_log.h"
#include "hi_type_dev.h"
#include "hi_tee_ssm.h"

hi_s32 hi_tee_drv_ssm_iommu_config(hi_tee_logic_mod_id module_id);

hi_s32 hi_tee_drv_ssm_attach_buf(const hi_tee_ssm_buffer_attach_info *buffer_attach_infor, hi_u64 *secure_info_addr);

#endif
