/*
 * hisilicon ISP driver, hisp_power.h
 *
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 *
 */

#ifndef _KIRIN_ISP_HISP_POWER_H_
#define _KIRIN_ISP_HISP_POWER_H_

#include <register_ops.h>
#include "secmem_priv.h"
#include "sre_typedef.h"

UINT32 hisp_top_pwron_and_disreset(struct smmu_domain *domain);
UINT32 hisp_top_pwroff_and_reset(struct smmu_domain *domain);
#endif

