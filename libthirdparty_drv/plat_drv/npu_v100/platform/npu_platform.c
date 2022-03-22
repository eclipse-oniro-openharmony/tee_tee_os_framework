/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu platform
 */

#include "npu_platform.h"
#include <string.h>
#include <errno.h>
#include <drv_module.h>

#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "securec.h"
#include "drv_log.h"
#include "npu_platform_resource.h"
#include "npu_platform_register.h"
#include "npu_adapter.h"
#include "npu_reg.h"
#include "npu_dfx.h"
#include "npu_resmem.h"
#include "npu_gic.h"
#include "npu_feature.h"
#include "npu_irq.h"

int npu_plat_init_adapter(struct npu_platform_info *plat_info)
{
	DEVDRV_PLAT_GET_RES_CHG_ROUTE(plat_info) = NULL;
	DEVDRV_PLAT_GET_RES_SQCQ_ALLOC(plat_info) = NULL;
	DEVDRV_PLAT_GET_RES_TIRG_IRQ(plat_info) = NULL;
	DEVDRV_PLAT_GET_RES_MAILBOX_SEND(plat_info) = npu_plat_res_mailbox_send;
	return 0;
}

int npu_plat_parse_dtsi(struct npu_platform_info *plat_info)
{
	int ret;

	if (plat_info == NULL) {
		NPU_ERR("invalid param plat_info is null\n");
		return -1;
	}
	ret = npu_plat_parse_reg_desc(plat_info);
	if (ret != 0) {
		NPU_ERR("npu_plat_parse_reg_desc failed\n");
		return ret;
	}

	ret = npu_plat_parse_irq(plat_info);
	if (ret != 0) {
		NPU_ERR("npu_plat_parse_irq failed\n");
		return ret;
	}

	ret = npu_plat_parse_resmem_desc(plat_info);
	if (ret != 0) {
		NPU_ERR("npu_plat_parse_resmem_desc failed\n");
		return ret;
	}

	ret = npu_plat_parse_gic(plat_info);
	if (ret != 0) {
		NPU_ERR("npu_parse_platform_gic failed\n");
		return ret;
	}

	ret = npu_plat_parse_feature_switch(plat_info);
	if (ret != 0) {
		NPU_ERR("npu_parse_platform_feature_switch failed\n");
		return ret;
	}

	return 0;
}

int npu_plat_init_spec(struct npu_platform_info *plat_info)
{
	DEVDRV_PLAT_GET_STREAM_MAX(plat_info) = DEVDRV_PLAT_STREAM_MAX;
	DEVDRV_PLAT_GET_EVENT_MAX(plat_info) = DEVDRV_PLAT_EVENT_MAX;
	DEVDRV_PLAT_GET_NOTIFY_MAX(plat_info) = DEVDRV_PLAT_NOTIFY_MAX;
	DEVDRV_PLAT_GET_MODEL_MAX(plat_info) = DEVDRV_PLAT_MODEL_MAX;
	DEVDRV_PLAT_GET_AICORE_MAX(plat_info) = DEVDRV_PLAT_AICORE_MAX;
	DEVDRV_PLAT_GET_AICPU_MAX(plat_info) = DEVDRV_PLAT_AICPU_MAX;
	DEVDRV_PLAT_GET_CALC_SQ_MAX(plat_info) = DEVDRV_PLAT_CALC_SQ_MAX;
	DEVDRV_PLAT_GET_CALC_SQ_DEPTH(plat_info) = DEVDRV_PLAT_CALC_SQ_DEPTH;
	DEVDRV_PLAT_GET_CALC_CQ_MAX(plat_info) = DEVDRV_PLAT_CALC_CQ_MAX;
	DEVDRV_PLAT_GET_CALC_CQ_DEPTH(plat_info) = DEVDRV_PLAT_CALC_CQ_DEPTH;
	DEVDRV_PLAT_GET_DFX_SQ_MAX(plat_info) = DEVDRV_PLAT_DFX_SQ_MAX;
	DEVDRV_PLAT_GET_DFX_CQ_MAX(plat_info) = DEVDRV_PLAT_DFX_CQ_MAX;
	DEVDRV_PLAT_GET_DFX_SQCQ_DEPTH(plat_info) = DEVDRV_PLAT_DFX_SQCQ_DEPTH;
	DEVDRV_PLAT_GET_DOORBELL_STRIDE(plat_info) = DEVDRV_PLAT_DOORBELL_STRIDE;
	return 0;
}

static struct npu_platform_info *s_platform_info = NULL;

int npu_platform_probe(void)
{
	int ret;
	struct npu_platform_info *platform_info = NULL;

	NPU_DEBUG("npu_platform_probe start\n");

	platform_info = (struct npu_platform_info *)TEE_Malloc(sizeof(struct npu_platform_info), 0);
	if (platform_info == NULL) {
		NPU_ERR("kzalloc plat_info failed\n");
		return -ENOMEM;
	}

	if (memset_s(platform_info, sizeof(struct npu_platform_info), 0, sizeof(struct npu_platform_info)) != EOK) {
		NPU_ERR("memset_s plat_info failed\n");
	}
	DEVDRV_PLAT_GET_TYPE(platform_info) = DEVDRV_PLAT_DEVICE;
	DEVDRV_PLAT_GET_ENV(platform_info) = DEVDRV_PLAT_TYPE_ASIC;
	DEVDRV_PLAT_GET_HARDWARE(platform_info) = (u32)SOC_HARDWARE_VERSION;

	ret = npu_plat_parse_dtsi(platform_info);
	if (ret != 0) {
		NPU_ERR("prase dtsi failed\n");
		goto PROB_FAIL;
	}

	ret = npu_plat_init_adapter(platform_info);
	if (ret != 0) {
		NPU_ERR("npu_plat_init_adapter failed\n");
		goto PROB_FAIL;
	}

	ret = npu_plat_init_spec(platform_info);
	if (ret != 0) {
		NPU_ERR("npu_plat_init_spec failed\n");
		goto PROB_FAIL;
	}

	s_platform_info = platform_info;

	npu_res_mem_init();

	NPU_DEBUG("npu_platform_probe succ\n");
	return 0;

PROB_FAIL:
	NPU_ERR("npu_platform_probe failed\n");
	TEE_Free(platform_info);
	platform_info = NULL;
	return ret;
}

struct npu_platform_info* npu_plat_get_info(void)
{
	return s_platform_info;
}

int npu_platform_remove(void)
{
	struct npu_platform_info *plat_info = NULL;

	NPU_DEBUG("npu_device_remove start\n");

	plat_info = npu_plat_get_info();
	if (plat_info == NULL) {
		NPU_INFO("npu_plat_get_info failed\n");
		return 0;
	}

	NPU_INFO("npu_device_remove succeed\n");

	TEE_Free(plat_info);

	return 0;
}
