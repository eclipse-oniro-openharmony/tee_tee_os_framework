/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display registe all the callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_DSS_MODULE_REGISTE_H
#define HISI_DSS_MODULE_REGISTE_H

#include "reg_dfc/hisi_dss_dfc.h"
#include "reg_dma/hisi_dss_dma.h"
#include "reg_ldi/hisi_dss_ldi.h"
#include "reg_mctl/hisi_dss_mctl.h"
#include "reg_mif/hisi_dss_mif.h"
#include "reg_ovl/hisi_dss_ovl.h"
#include "reg_smmu/hisi_dss_smmu.h"
#include "reg_mix/hisi_dss_mix.h"

struct hisi_dss_module_cb {
	struct dss_dfc_cb dfc_cb;
	struct dss_dma_cb dma_cb;
	struct dss_ldi_cb ldi_cb;
	struct dss_mctl_cb mctl_cb;
	struct dss_mif_cb mif_cb;
	struct dss_ovl_cb ovl_cb;
	struct dss_smmu_cb smmu_cb;
	struct dss_mix_cb mix_cb;
};

void dss_registe_module_cb(void);
struct hisi_dss_module_cb *dss_get_module_cb(void);

#endif
