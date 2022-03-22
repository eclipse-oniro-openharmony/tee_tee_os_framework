/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description:about npu adapter
 */

#include "npu_adapter.h"
#include "list.h"
#include <errno.h>
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include <drv_mem.h> // sre_mmap
#include "drv_pal.h" /* task_caller */

#include "npu_common.h"
#include "npu_platform_resource.h"
#include "npu_platform_register.h"
#include "sre_syscalls_ext.h"
#include "svm.h"
#include "npu_platform_external.h"
#include "npu_reg.h"
#include "soc_smmuv3_tbu_interface.h"
#include "npu_ddr_map.h"

#define NPU_SVC_OK              0
#define NPU_SVC_ERR             (~NPU_SVC_OK)

typedef union {
	struct {
		uint32_t npu_sec_enable;
	} cfg;
	unsigned char reserved[NPU_S_NPU_CONFIG_SIZE];
} npu_secmem_head;

int npu_power_up_aic_tbu(void)
{
	int ret = -1;
	uint32_t tok_trans_gnt = 0;

	// initial
	npu_reg_update(SOC_SMMUV3_SMMU_TBU_CR_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR),
		NPU_TBU_MAX_TOK_TRANS_MASK, NPU_AIC_TBU_MAX_TOK_TRANS);

	npu_reg_update(SOC_SMMUV3_SMMU_TBU_CR_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR),
		NPU_TBU_EN_REQ_MASK, NPU_TBU_EN_REQ);

	ret = npu_read_wait(SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR),
		SMMU_TBU_EN_ACK_MASK, SMMU_TBU_EN_ACK_VAL, 100);
	if (ret != NPU_SVC_OK) {
		NPU_ERR("SOC_SMMUV3_SMMU_TBU_CRACK_ADDR1 fail!");
		return ret;
	}

	ret = npu_read_wait(SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR),
		SMMU_TBU_CONNECTED_STATE_MASK, SMMU_TBU_CONNECTED_VAL, 10);
	if (ret != NPU_SVC_OK) {
		NPU_ERR("tbu connect fail!");
		return ret;
	}

	tok_trans_gnt = hisi_readl(SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR));
	tok_trans_gnt = (tok_trans_gnt & 0xFF00);
	if (tok_trans_gnt < NPU_AIC_TBU_MAX_TOK_TRANS) {
		NPU_ERR("tok_trans_gnt value : 0x%lx", tok_trans_gnt);
		return ret;
	}

	// swid config
	npu_reg_update(SOC_SMMUV3_SMMU_TBU_CR_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR),
		NPU_AIC_TBU_PREFSLOT_FULL_LEVEL_MASK, NPU_AIC_TBU_PREFSLOT_FULL_LEVEL);

	npu_reg_update(SOC_SMMUV3_SMMU_TBU_CR_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR),
		NPU_AIC_TBU_FETCHFSLOT_FULL_LEVEL_MASK, NPU_AIC_TBU_FETCHFSLOT_FULL_LEVEL);

	// prefetch enable, npu swid: 0~17
	for (int m = 0; m < NPU_SWID_MAX_CNT; m++)
		npu_reg_update(SOC_SMMUV3_SMMU_TBU_SWID_CFG(SMMU_AICORE_TBU_CTRL_BASE_ADDR, m),
			NPU_TBU_PREF_ENABLE_MASK, NPU_TBU_PREF_ENABLE);
	// syscache_hint_sel

	// interrupt config
	hisi_writel(0xFFFFFFFF, SOC_SMMUv3_TBU_SMMU_TBU_IRPT_CLR_S_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR));
	hisi_writel(0x0, SOC_SMMUv3_TBU_SMMU_TBU_IRPT_MASK_S_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR));

	return ret;
}


int npu_power_up_sysdma_tbu(void)
{
	int ret = -1;
	uint32_t tok_trans_gnt = 0;
	// initial
	npu_reg_update(SOC_SMMUV3_SMMU_TBU_CR_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR),
		NPU_TBU_MAX_TOK_TRANS_MASK, NPU_AIC_TBU_MAX_TOK_TRANS);

	npu_reg_update(SOC_SMMUV3_SMMU_TBU_CR_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR),
			NPU_TBU_EN_REQ_MASK, NPU_TBU_EN_REQ);

	ret = npu_read_wait(SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR),
		SMMU_TBU_EN_ACK_MASK, SMMU_TBU_EN_ACK_VAL, 100);
	if (ret != NPU_SVC_OK) {
		NPU_ERR("SOC_SMMUV3_SMMU_TBU_CRACK_ADDR1 fail!");
		return ret;
	}

	ret = npu_read_wait(SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR),
		SMMU_TBU_CONNECTED_STATE_MASK, SMMU_TBU_CONNECTED_VAL, 10);
	if (ret != NPU_SVC_OK) {
		NPU_ERR("tbu connect fail!");
		return ret;
	}

	tok_trans_gnt = hisi_readl(SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR));
	tok_trans_gnt = (tok_trans_gnt & 0xFF00);
	if (tok_trans_gnt < NPU_AIC_TBU_MAX_TOK_TRANS) {
		NPU_ERR("tok_trans_gnt value : 0x%lx", tok_trans_gnt);
		return ret;
	}

	// swid config
	npu_reg_update(SOC_SMMUV3_SMMU_TBU_CR_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR),
		NPU_AIC_TBU_PREFSLOT_FULL_LEVEL_MASK, NPU_AIC_TBU_PREFSLOT_FULL_LEVEL);

	npu_reg_update(SOC_SMMUV3_SMMU_TBU_CR_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR),
		NPU_AIC_TBU_FETCHFSLOT_FULL_LEVEL_MASK, NPU_AIC_TBU_FETCHFSLOT_FULL_LEVEL);

	// prefetch enable, npu swid: 0~17
	for (int m = 0; m < NPU_SWID_MAX_CNT; m++)
		npu_reg_update(SOC_SMMUV3_SMMU_TBU_SWID_CFG(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR, m),
			NPU_TBU_PREF_ENABLE_MASK, NPU_TBU_PREF_ENABLE);
	// syscache_hint_sel

	// interrupt config
	hisi_writel(0xFFFFFFFF, SOC_SMMUv3_TBU_SMMU_TBU_IRPT_CLR_S_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR));
	hisi_writel(0x0, SOC_SMMUv3_TBU_SMMU_TBU_IRPT_MASK_S_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR));
	return ret;
}


int npu_power_up_smmu_tbu()
{
	int ret = 0;

	npu_power_up_aic_tbu();
	npu_power_up_sysdma_tbu();

	return ret;
}


int npu_power_down_smmu_tbu()
{
	int ret = -1;

	npu_reg_update(SOC_SMMUV3_SMMU_TBU_CR_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR),
			NPU_TBU_EN_REQ_MASK, NPU_TBU_DISABLE_REQ);

	ret = npu_read_wait(SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR),
		SMMU_TBU_EN_ACK_MASK, SMMU_TBU_EN_ACK_VAL, 100);
	if (ret != NPU_SVC_OK) {
		NPU_ERR("tbu disable fail!");
		return ret;
	}

	ret = npu_read_wait(SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR),
		SMMU_TBU_CONNECTED_STATE_MASK, SMMU_TBU_DISCONNECTED_VAL, 1);
	if (ret != NPU_SVC_OK) {
		NPU_ERR("tbu and tcu disconnect fail!");
		return ret;
	}

	npu_reg_update(SOC_SMMUV3_SMMU_TBU_CR_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR),
			NPU_TBU_EN_REQ_MASK, NPU_TBU_DISABLE_REQ);

	ret = npu_read_wait(SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR),
		SMMU_TBU_EN_ACK_MASK, SMMU_TBU_EN_ACK_VAL, 100);
	if (ret != NPU_SVC_OK) {
		NPU_ERR("tbu disable fail!");
		return ret;
	}

	ret = npu_read_wait(SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR),
		SMMU_TBU_CONNECTED_STATE_MASK, SMMU_TBU_DISCONNECTED_VAL, 1);
	if (ret != NPU_SVC_OK) {
		NPU_ERR("tbu and tcu disconnect fail!");
		return ret;
	}

	return ret;
}

int npu_plat_power_up(void *svm_dev)
{
	struct tee_svm_para_list *svm_para_list = NULL;
	uint32_t ta_pid = 0;
	int ret = -1;

	NPU_INFO("npu_plat_power_up enter");
	if (svm_dev == NULL) {
		NPU_ERR("svm para list is null");
		return ret;
	}

	if (npu_pm_query_ree_status() != NPU_POWER_ON) {
		NPU_ERR("npu is power down, unable to powerup smmu");
		return ret;
	}

	svm_para_list = (struct tee_svm_para_list *)svm_dev;
	svm_para_list->smmuid = svm_sdma;
	// power on sdma/aicore smmu
	ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_ON, svm_para_list);
	if (ret) {
		NPU_ERR("tee npu sdma smmu svm power on failed, ret = %d", ret);
		return ret;
	}

	ret = npu_power_up_smmu_tbu();
	if (ret)
		NPU_ERR("tee npu sdma smmu tbu power on failed, ret = %d", ret);

	ret = SRE_TaskSelf(&ta_pid);
	if (ret < 0) {
		NPU_ERR("get ta pid failed in %s\n", __func__);
		goto get_ta_pid_failed;
	}

	// bind tee task
	svm_para_list->pid = ta_pid;
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
	if (__teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list))
		NPU_ERR("aicore_smmu_poweron_failed teesvm_ioctl SVM_SEC_CMD_POWER_OFF failed");

	return ret;
}

int npu_plat_power_down(void *svm_dev)
{
	struct tee_svm_para_list *svm_para_list = NULL;
	int svm_clear_ret;
	int unbind_ret;
	int sdma_ret;

	NPU_INFO("enter");

	if (svm_dev == NULL) {
		NPU_ERR("svm para list is null");
		return -1;
	}
	svm_para_list = (struct tee_svm_para_list *)svm_dev;

	if (npu_pm_query_ree_status() != NPU_POWER_ON) {
		NPU_ERR("npu is power down");
		// clear svm
		svm_clear_ret = __teesvm_ioctl(SVM_SEC_CMD_CLEAR_RES, svm_para_list);
		if (svm_clear_ret)
			NPU_ERR("npu svm clear failed, ret = %d", svm_clear_ret);

		return 0;
	}

	// unbind tee task
	unbind_ret = __teesvm_ioctl(SVM_SEC_CMD_UNBIND, svm_para_list);
	if (unbind_ret)
		NPU_ERR("tee hisi npu task bind failed, ret = %d", unbind_ret);

	svm_para_list->smmuid = svm_sdma;

	sdma_ret = npu_power_down_smmu_tbu();
	if (sdma_ret)
		NPU_ERR("tee npu sdma smmu tbu power down failed, ret = %d", sdma_ret);

	// power off sdma/aicore smmu
	sdma_ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list);
	if (sdma_ret)
		NPU_ERR("tee npu sdma smmu svm power off failed, ret = %d", sdma_ret);

	if (unbind_ret != 0 || sdma_ret != 0) {
		unbind_ret = (int)(unbind_ret + sdma_ret);
		NPU_ERR("tee hisi smmu power off failed. ret = %d\n", unbind_ret);
	}

	NPU_INFO("success");
	return 0;
}

int npu_plat_res_mailbox_send(void *mailbox, int mailbox_len,
                              const void *message, int message_len)
{
	u8 *message_buf = NULL;
	int message_block_number;
	uint32_t *mailbox_block = NULL;
	uint32_t *message_block = NULL;

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
		NPU_ERR("message buf alloc failed");
		return -1;
	}
	if (memset_s(message_buf, message_len, 0, mailbox_len) != EOK)
		NPU_ERR("memset_s message_buf failed");

	if (memcpy_s(message_buf, message_len, message, message_len) != EOK)
		NPU_ERR("memcpy_s message_buf failed");

	message_block_number = mailbox_len / sizeof(uint32_t);
	message_block = (uint32_t *)message_buf;
	mailbox_block = (uint32_t *)mailbox;
	for (int i = 0; i < message_block_number; i++)
		mailbox_block[i] = message_block[i];

	mb();
	TEE_Free(message_buf);
	return 0;
}

int npu_plat_sec_enable_status(void)
{
	int ret;
	static npu_secmem_head *head = NULL;
	u32 head_length = sizeof(npu_secmem_head);
	uintptr_t phy_base = NPU_SEC_RESERVED_DDR_BASE_ADDR;

	if (head != NULL)
		return head->cfg.npu_sec_enable;

	ret = sre_mmap((paddr_t)phy_base, head_length,
		(uint32_t *)(&head), secure, non_cache);
	COND_RETURN_ERROR(head == NULL, -EINVAL, "ioremap error, pa:0x%lx, size:0x%x\n",
		phy_base, head_length);

	return head->cfg.npu_sec_enable;
}
