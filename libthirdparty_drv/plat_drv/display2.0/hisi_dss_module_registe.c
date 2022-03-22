/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display registe all the callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_dss_module_registe.h"

struct hisi_dss_module_cb g_module_cb;

void dss_registe_module_cb(void)
{
	dss_registe_base_dfc_cb(&g_module_cb.dfc_cb);
	dss_registe_base_dma_cb(&g_module_cb.dma_cb);
	dss_registe_base_ldi_cb(&g_module_cb.ldi_cb);
	dss_registe_base_mctl_cb(&g_module_cb.mctl_cb);
	dss_registe_base_mif_cb(&g_module_cb.mif_cb);
	dss_registe_base_ovl_cb(&g_module_cb.ovl_cb);
	dss_registe_base_smmu_cb(&g_module_cb.smmu_cb);
	dss_registe_base_mix_cb(&g_module_cb.mix_cb);
}

struct hisi_dss_module_cb *dss_get_module_cb(void)
{
	return &g_module_cb;
}

