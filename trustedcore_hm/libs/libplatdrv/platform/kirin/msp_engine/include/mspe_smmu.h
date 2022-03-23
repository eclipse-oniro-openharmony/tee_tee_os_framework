/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declaration of smmu
 * Author: Security Engine
 * Create: 2020/10/27
 */
#ifndef MSPE_SMMU_H
#define MSPE_SMMU_H

#ifdef CONFIG_HISI_MSPE_SMMUV2
#include "mspe_smmu_v2.h"
#endif

#ifdef CONFIG_HISI_MSPE_SMMUV3
static inline void mspe_smmu_bypass(void) {}
#include "mspe_smmu_v3.h"
#endif

#endif
