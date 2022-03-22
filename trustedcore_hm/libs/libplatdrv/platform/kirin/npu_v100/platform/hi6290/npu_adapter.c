/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu adapter
 */

#include "list.h"
#include <errno.h>
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "drv_pal.h" /* task_caller */

#include "npu_common.h"
#include "npu_platform_resource.h"
#include "npu_platform_register.h"
#include "npu_adapter.h"
#include "sre_syscalls_ext.h"
#include "svm.h"
#include "npu_platform_external.h"
#include "npu_reg.h"

#define NPU_SVC_OK              0
#define NPU_SVC_ERR             (~NPU_SVC_OK)

#define SMMU_TCU_CTRL_SCR       0xe5f70090
#define SMMU_TCU_SCR            0xe5f48e18
#define SMMU_S_INIT             0xe5f4803c
#define SMMU_TCU_NODE_STATUS    0xe5f49400
#define SMMU_LP_REQ             0xe5f70000
#define SMMU_LP_ACK             0xe5f70004

#define TCU_QACCEPTN_CG               (1 << 0)
#define TCU_QACCEPTN_PD               (1 << 4)
#define TCU_QREQN_CG                  (1 << 0)
#define TCU_QREQN_PD                  (1 << 1)

#define SMMU_TCU_CTRL_SCR_UARCH_NS    (1 << 0)
#define TCU_CACHE_INV                 (1 << 0)
#define TBU_IS_CONNECTED              (1 << 0)
#define SMMU_TCU_SCR_NS               9
#define TBU_MAX_NUM                   13
#define MAX_CHECK_TIMES               100

/* Size: 128K, End at: 0xE5F3FFFF */
#define SOC_CPU_SYSDMA_TBU_BASE_ADDR                          0xE5F20000
/* Size: 128K, End at: 0xE5F1FFFF */
#define SOC_CPU_AIC_TBU_BASE_ADDR                             0xE5F00000
#define SMMU_AICORE_TBU_CTRL_BASE_ADDR    (SOC_CPU_AIC_TBU_BASE_ADDR + 0x10000)
#define SMMU_SYSDMA_TBU_CTRL_BASE_ADDR    (SOC_CPU_SYSDMA_TBU_BASE_ADDR + 0x10000)

#define SOC_SMMUV3_SMMU_TBU_SCR_ADDR(base)                    ((base) + (0x1000UL))
#define SOC_SMMUV3_SMMU_TBU_CR_ADDR(base)                     ((base) + (0x0000UL))
#define SOC_SMMUV3_SMMU_TBU_CRACK_ADDR(base)                  ((base) + (0x0004UL))
#define SOC_SMMUV3_SMMU_TBU_SWID_CFG(base, m)                 ((base) + ((0x100UL) + (m) * 4UL))

#define SOC_IOMCU_SCTRL_NPU_BASE_ADDR                         0xE5E04000
#define SOC_NPU_SCTRL_NPU_CTRL18_ADDR(base)                   ((base) + (0x048UL))
#define SOC_NPU_SCTRL_NPU_CTRL19_ADDR(base)                   ((base) + (0x04CUL))


#define NPU_AIC_TBU_MAX_TOK_TRANS                             (0x18 << 8)
#define NPU_SYSDMA_TBU_MAX_TOK_TRANS                          (0x18 << 8)
#define NPU_TBU_MAX_TOK_TRANS_MASK                            0xFF00

#define NPU_TBU_NS_UARCH_MASK                                 0x1

#define NPU_TBU_EN_REQ                                        0x1
#define NPU_TBU_DISABLE_REQ                                   0x0
#define NPU_TBU_EN_REQ_MASK                                   0x1

#define NPU_AIC_TBU_PREFSLOT_FULL_LEVEL                       (0x18 << 24)
#define NPU_AIC_TBU_PREFSLOT_FULL_LEVEL_MASK                  0x3F000000
#define NPU_TBU_PREF_ENABLE                                   0x80000000
#define NPU_TBU_PREF_ENABLE_MASK                              0x80000000

#define NPU_AIC_TBU_FETCHFSLOT_FULL_LEVEL                     (0x18 << 16)
#define NPU_AIC_TBU_FETCHFSLOT_FULL_LEVEL_MASK                0x3F0000

#define NPU_SID_MASK                                          0x3FFFF
#define SMMU_TBU_EN_ACK_MASK                                  0x1
#define SMMU_TBU_EN_ACK_VAL                                   0x1
#define SMMU_TBU_CONNECTED_STATE_MASK                         0x2
#define SMMU_TBU_CONNECTED_VAL                                0x2
#define SMMU_TBU_DISCONNECTED_VAL                             0x0

#define NPU_SWID_MAX_CNT                                      18

int npu_power_up_aic_tbu(void)
{
	int ret = -1;
	uint32_t tok_trans_gnt = 0;

	// initial
	npu_reg_update(SOC_SMMUV3_SMMU_TBU_SCR_ADDR(SMMU_AICORE_TBU_CTRL_BASE_ADDR),
		NPU_TBU_NS_UARCH_MASK, NPU_TBU_EN_REQ);

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
	for(int m = 0; m < NPU_SWID_MAX_CNT; m++)
		npu_reg_update(SOC_SMMUV3_SMMU_TBU_SWID_CFG(SMMU_AICORE_TBU_CTRL_BASE_ADDR, m),
			NPU_TBU_PREF_ENABLE_MASK, NPU_TBU_PREF_ENABLE);
	// syscache_hint_sel

	// interrupt config
	hisi_writel(0xFFFFFFFF, SMMU_AICORE_TBU_CTRL_BASE_ADDR + 0x1c);
	hisi_writel(0x0, SMMU_AICORE_TBU_CTRL_BASE_ADDR + 0x10);
	hisi_writel(0xFFFFFFFF, SMMU_AICORE_TBU_CTRL_BASE_ADDR + 0x101c);
	hisi_writel(0x0, SMMU_AICORE_TBU_CTRL_BASE_ADDR + 0x1010);

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
	for(int m = 0; m < NPU_SWID_MAX_CNT; m++)
		npu_reg_update(SOC_SMMUV3_SMMU_TBU_SWID_CFG(SMMU_SYSDMA_TBU_CTRL_BASE_ADDR, m),
			NPU_TBU_PREF_ENABLE_MASK, NPU_TBU_PREF_ENABLE);
	// syscache_hint_sel

	// interrupt config
	hisi_writel(0xFFFFFFFF, SMMU_SYSDMA_TBU_CTRL_BASE_ADDR + 0x1c);
	hisi_writel(0x0, SMMU_SYSDMA_TBU_CTRL_BASE_ADDR + 0x10);
	hisi_writel(0xFFFFFFFF, SMMU_SYSDMA_TBU_CTRL_BASE_ADDR + 0x101c);
	hisi_writel(0x0, SMMU_SYSDMA_TBU_CTRL_BASE_ADDR + 0x1010);
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
	// power on sdma/aicore smmu
	ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_ON,svm_para_list);
	if (ret) {
		NPU_ERR("tee npu sdma smmu svm power on failed, ret = %d", ret);
		return ret;
	}

	ret = npu_power_up_smmu_tbu();
	if (ret) {
		NPU_ERR("tee npu sdma smmu tbu power on failed, ret = %d", ret);
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
	if (__teesvm_ioctl(SVM_SEC_CMD_POWER_OFF,svm_para_list)) {
		NPU_ERR("aicore_smmu_poweron_failed teesvm_ioctl SVM_SEC_CMD_POWER_OFF failed");
	}
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

	sdma_ret = npu_power_down_smmu_tbu();
	if (sdma_ret) {
		NPU_ERR("tee npu sdma smmu tbu power down failed, ret = %d", sdma_ret);
	}
	// power off sdma/aicore smmu
	sdma_ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list);
	if (sdma_ret) {
		NPU_ERR("tee npu sdma smmu svm power off failed, ret = %d", sdma_ret);
	}

	if (unbind_ret != 0 || sdma_ret != 0) {
		unbind_ret = (int)(unbind_ret + sdma_ret);
		NPU_ERR("tee hisi smmu power off failed. ret = %d\n",unbind_ret);
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

	NPU_DEBUG("mailbox send_sram_addr = %p",mailbox);
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
