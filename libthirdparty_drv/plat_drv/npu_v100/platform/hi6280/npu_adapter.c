/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu adapter
 */

#include "npu_adapter.h"

#include <errno.h>
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "sre_syscalls_ext.h"
#include "drv_pal.h"
#include "svm.h"
#include "npu_common.h"
#include "npu_platform_resource.h"
#include "npu_platform_register.h"
#include "npu_platform_external.h"

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
	svm_para_list = (struct tee_svm_para_list *)svm_dev;
	svm_para_list->smmuid = svm_sdma;
	// power on sdma/aicore smmu
	ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_ON, svm_para_list);
	if (ret) {
		NPU_ERR("tee npu sdma smmu svm power on failed, ret = %d", ret);
		return ret;
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
	svm_para_list->smmuid = svm_sdma;
	if (__teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list)) {
		NPU_ERR("aicore_smmu_poweron_failed teesvm_ioctl SVM_SEC_CMD_POWER_OFF failed");
	}
	return ret;
}

int npu_plat_power_down(void *svm_dev)
{
	struct tee_svm_para_list *svm_para_list = NULL;
	int unbind_ret;
	int sdma_ret;

	NPU_INFO("npu_plat_power_down enter");

	if (svm_dev == NULL) {
		NPU_ERR("svm para list is null");
		return -1;
	}
	svm_para_list = (struct tee_svm_para_list *)svm_dev;

	// unbind tee task
	unbind_ret = __teesvm_ioctl(SVM_SEC_CMD_UNBIND, svm_para_list);
	if (unbind_ret) {
		NPU_ERR("tee hisi npu task bind failed, ret = %d", unbind_ret);
	}

	svm_para_list->smmuid = svm_sdma;
	// power off sdma/aicore smmu
	sdma_ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list);
	if (sdma_ret) {
		NPU_ERR("tee npu sdma smmu svm power off failed, ret = %d", sdma_ret);
	}

	if (unbind_ret != 0 || sdma_ret != 0) {
		unbind_ret = (int)(unbind_ret + sdma_ret);
		NPU_ERR("tee hisi smmu power off failed. ret = %d\n", unbind_ret);
	}

	NPU_INFO("npu_plat_power_down success");
	return 0;
}

int npu_plat_res_mailbox_send(void *mailbox, int mailbox_len,
                              const void *message, int message_len)
{
	u8 *message_buf = NULL;
	int message_block_number;
	uint32_t *mailbox_block = NULL;
	uint32_t *message_block = NULL;

	NPU_INFO("mailbox send_sram_addr = %p", mailbox);
	if (message_len > mailbox_len) {
		NPU_ERR("message len =%d, too long", message_len);
		return -1;
	}

	if (mailbox == NULL) {
		NPU_ERR("mailbox is NULL");
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

	message_block_number = mailbox_len / sizeof(uint32_t);
	message_block = (uint32_t *)message_buf;
	mailbox_block = (uint32_t *)mailbox;
	for (int i = 0; i < message_block_number; i++) {
		mailbox_block[i] = message_block[i];
	}

	mb();
	TEE_Free(message_buf);
	return 0;
}

int npu_plat_sec_enable_status(void)
{
	return NPU_SEC_FEATURE_SUPPORTED;
}
