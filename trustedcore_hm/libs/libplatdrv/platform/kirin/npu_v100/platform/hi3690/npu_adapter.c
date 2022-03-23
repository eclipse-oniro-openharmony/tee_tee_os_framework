/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu adapter
 */

#include "npu_adapter.h"

#include <errno.h>
#include "sre_syscalls_ext.h"
#include "svm.h"
#include "tee_mem_mgmt_api.h"
#include "drv_pal.h"

#include "npu_common.h"
#include "npu_platform_resource.h"
#include "npu_platform_register.h"
#include "npu_platform_external.h"
#include "npu_reg.h"

int npu_plat_power_up(void *svm_dev)
{
	struct tee_svm_para_list *svm_para_list = NULL;
	uint32_t ta_pid = 0;
	int ret;

	NPU_INFO("npu_plat_power_up enter");
	if (svm_dev == NULL) {
		NPU_ERR("svm para list is null");
		return -1;
	}

	if (npu_pm_query_ree_status() != NPU_POWER_ON) {
		NPU_ERR("npu is power down, unable to powerup smmu");
		return -1;
	}

	svm_para_list = (struct tee_svm_para_list *)svm_dev;
	svm_para_list->smmuid = svm_sdma;
	// power on sdma smmu
	ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_ON, svm_para_list);
	if (ret) {
		NPU_ERR("tee npu sdma smmu svm power on failed, ret = %d", ret);
		return ret;
	}

	// power on aicore smmu
	svm_para_list->smmuid = svm_ai;
	ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_ON, svm_para_list);
	if (ret) {
		NPU_ERR("tee npu aicore smmu svm power on failed, ret = %d", ret);
		goto aicore_smmu_poweron_failed;
	}

	ret = SRE_TaskSelf(&ta_pid);
	if (ret < 0) {
		NPU_ERR("get ta pid failed in %s\n", __func__);
		goto get_ta_pid_failed;
	}

	// bind tee task
	svm_para_list->pid = ta_pid; // is ta pid or drv pid ?
	ret = __teesvm_ioctl(SVM_SEC_CMD_BIND, svm_para_list);
	if (ret) {
		NPU_ERR("tee hisi npu task bind failed, ret = %d", ret);
		goto smmu_bind_failed;
	}

	NPU_INFO("npu_plat_power_up success");

	return 0;

smmu_bind_failed:
get_ta_pid_failed:
	svm_para_list->smmuid = svm_ai;
	if (__teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list)) {
		NPU_ERR("get_ta_pid_failed teesvm_ioctl SVM_SEC_CMD_POWER_OFF failed");
	}
aicore_smmu_poweron_failed:
	svm_para_list->smmuid = svm_sdma;
	if (__teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list)) {
		NPU_ERR("aicore_smmu_poweron_failed teesvm_ioctl SVM_SEC_CMD_POWER_OFF failed");
	}
	return ret;
}

int npu_plat_power_down(void *svm_dev)
{
	struct tee_svm_para_list *svm_para_list = NULL;
	int svm_clear_ret;
	int unbind_ret;
	int aicore_ret;
	int sdma_ret;

	NPU_INFO("npu_plat_power_down enter");

	if (svm_dev == NULL) {
		NPU_ERR("svm para list is null");
		return -1;
	}
	svm_para_list = (struct tee_svm_para_list *)svm_dev;

	if (npu_pm_query_ree_status() != NPU_POWER_ON) {
		NPU_ERR("npu is power down");
		// clear svm
		svm_clear_ret = __teesvm_ioctl(SVM_SEC_CMD_CLEAR_RES, svm_para_list);
		if (svm_clear_ret) {
			NPU_ERR("npu svm clear failed, ret = %d", svm_clear_ret);
		}
		return 0;
	}

	// unbind tee task
	unbind_ret = __teesvm_ioctl(SVM_SEC_CMD_UNBIND, svm_para_list);
	if (unbind_ret) {
		NPU_ERR("tee hisi npu task bind failed, ret = %d", unbind_ret);
	}

	svm_para_list->smmuid = svm_sdma;
	// power off sdma smmu
	sdma_ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list);
	if (sdma_ret) {
		NPU_ERR("tee npu sdma smmu svm power off failed, ret = %d", sdma_ret);
	}

	// power off aicore smmu
	svm_para_list->smmuid = svm_ai;
	aicore_ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list);
	if (aicore_ret) {
		NPU_ERR("tee npu aicore smmu svm power off failed, ret = %d", aicore_ret);
	}

	if (unbind_ret != 0 || sdma_ret != 0 || aicore_ret != 0) {
		unbind_ret = (int)(unbind_ret + sdma_ret + aicore_ret);
		NPU_ERR("tee hisi smmu power off failed. ret = %d\n", unbind_ret);
	}

	NPU_INFO("npu_plat_power_down success");
	return 0;
}

int npu_plat_res_mailbox_send(void *mailbox, int mailbox_len,
                              const void *message, int message_len)
{
	u8 *message_buf = NULL;

	NPU_DEBUG("mailbox send_sram_addr = %p", mailbox);
	if (message_len > mailbox_len) {
		NPU_ERR("message len =%d, too long", message_len);
		return -1;
	}

	if (mailbox == NULL) {
		NPU_ERR("mailbox is NULL");
		return -1;
	}

	if (npu_pm_query_ree_status() != NPU_POWER_ON) {
		NPU_ERR("npu is power down, unable to send mailbox");
		return -1;
	}

	message_buf = TEE_Malloc(mailbox_len, 0);
	if (message_buf == NULL) {
		NPU_ERR("message buf alloc failed.");
		return -1;
	}
	if (memset_s(message_buf, message_len, 0, mailbox_len) != EOK) {
		NPU_ERR("memset_s message_buf failed.");
	}
	if (memcpy_s(message_buf, message_len, message, message_len) != EOK) {
		NPU_ERR("memcpy_s message_buf failed.");
	}
	if (memcpy_s(mailbox, mailbox_len, message_buf, mailbox_len) != EOK) {
		NPU_ERR("memcpy_s mailbox failed.");
	}
	mb();
	TEE_Free(message_buf);
	return 0;
}

int npu_plat_sec_enable_status(void)
{
	return NPU_SEC_FEATURE_SUPPORTED;
}
