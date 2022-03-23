/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ufsc driver for FBE3
 * Author: LAI Xinyi
 * Create: 2020/01/07
 */

#include "sec_fbe3_ufsc.h"

#include <sre_typedef.h>
#include <sre_sys.h>
#include <register_ops.h>
#include <tee_log.h>
#include <hisi_boot.h>
#include <sys/usrsyscall_new_ext.h>
#include <sys/usrsyscall_ext.h>
#include "libdrv_frame.h"

#ifdef CONFIG_FBE_UFS_KEY_WORKAROUND

static int ufs_disable_local_irq(void)
{
	int rc;
	rref_t ctrl_ref;

	ctrl_ref = get_sysctrl_hdlr();
	if (is_ref_err(ctrl_ref)) {
		tloge("ufs: sys ctrl channel is not ready\n");
		return -1;
	}

	rc = hmex_disable_local_irq(ctrl_ref, hm_tcb_get_cref());
	if (rc) {
		tloge("ufs: hmex_disable_local_irq failed: %s\n",
		      hmapi_strerror(rc));
		return -1;
	}

	tlogd("ufs: get hwspinlock succ\n");
	return 0;
}

static void ufs_enable_local_irq(void)
{
	int rc;
	rref_t ctrl_ref;

	ctrl_ref = get_sysctrl_hdlr();
	if (is_ref_err(ctrl_ref)) {
		tloge("ufs: sys ctrl channel is not ready\n");
		return;
	}

	rc = hmex_enable_local_irq(ctrl_ref, hm_tcb_get_cref());
	if (rc)
		tloge("ufs: hmex_enable_local_irq failed: %s\n", hmapi_strerror(rc));

	return;
}

static void ufs_run_stop_config(int flag)
{
	UINT32 k;
	UINT32 val = (flag == UFS_DATA_STOP) ? 0 : 1;

	for (k = 0; k < UFS_CORE_NUM; k++)
		writel(val, UFS_CORE_UTRLRSR(k));
}

static void ufs_data_transfer_start(void)
{
	UINT32 k;
	UINT32 val;
	int ret;

	ret = ufs_disable_local_irq();
	writel(0, UFS_HW_PRESS_CFG);
	ufs_run_stop_config(UFS_DATA_START);
	if (!ret)
		ufs_enable_local_irq();

	writel(AHIT_EXIT_REQ, UFS_AHIT_EXIT_REQ);
	for (k = 0; k < UFS_AH8_RETRY_MAX; k++) {
		val = auto_h8_state(readl(UFS_AUTO_H8_STATE));
		if (val == AH8_XFER || val == AH8_IDLE) {
			writel(0, UFS_AHIT_EXIT_REQ);
			return;
		}
		SRE_DelayMs(1);
	}
	writel(0, UFS_AHIT_EXIT_REQ);
	tloge("ufs auto h8 exit fail:0x%x\n", val);
	return;
}

static void ufs_data_transfer_stop(void)
{
	UINT32 k;
	UINT32 val;
	int ret;

	ret = ufs_disable_local_irq();
	ufs_run_stop_config(UFS_DATA_STOP);
	writel(UFS_UTP_PRESS, UFS_HW_PRESS_CFG);
	if (!ret)
		ufs_enable_local_irq();

	val = readl(UFS_TRP_DFX1);
	if (!(val & UTP_FIFO_FULL)) {
		for (k = 0; k < UFS_RETRY_MAX; k++) {
			if (cmd_state(readl(UFS_TRP_DFX1)) == 0 &&
			    dma0_read_is_empty(readl(UFS_DMA0_DFX0)))
				break;
			hisi_udelay(100);
		}
		if (k >= UFS_RETRY_MAX)
			tloge("ufs wait timeout UFS_TRP_DFX1:0x%x, UFS_DMA0_DFX0:0x%x\n",
			      readl(UFS_TRP_DFX1), readl(UFS_DMA0_DFX0));
	}

	for (k = 0; k < UFS_RETRY_MAX; k++) {
		if ((utp_tx_outstanding(readl(UFS_UTP_TX_DFX1)) == 0) &&
		    (utp_rx_fsm(readl(UFS_UTP_RX_DFX2)) == UNIIF_IDLE_STATE))
			break;
		hisi_udelay(30);
	}
	if (k >= UFS_RETRY_MAX)
		tloge("ufs wait timeout UFS_TRP_DFX1:0x%x, UFS_DMA0_DFX0:0x%x,"
		      "UFS_UTP_TX_DFX1:0x%x, UFS_UTP_RX_DFX2:0x%x\n",
		      readl(UFS_TRP_DFX1), readl(UFS_DMA0_DFX0),
		      readl(UFS_UTP_TX_DFX1), readl(UFS_UTP_RX_DFX2));
}

static void ufs_data_transfer_config(int enable)
{
	if (enable == UFS_DATA_STOP)
		ufs_data_transfer_stop();
	else
		ufs_data_transfer_start();
}
#else
static inline void ufs_data_transfer_config(int enable)
{
}
#endif

/*
 * set the key into the x-CRYPTOCFG of UFS controller.
 * return: 0 - success, 1 - some error occurs
 */

UINT32 file_encry_config_ufsc(UINT32 ufs_slot, UINT8 *key, UINT32 length)
{
	UINT32 reg_value;
	uintptr_t key_reg_addr;
	UINT32 i;

	if (ufs_slot >= MAX_CRYPTO_KEY_INDEX || length != AES_DECKEY_LEN ||
	    !key) {
		tloge("ufs inline crypt key index is invalid.\n");
		return 1;
	}
	/*
	 * the key slot distance is 0x80.
	 * key operation start, check bit31
	 */
	tloge("%s, config ckey to slot 0x%x\n", __func__, ufs_slot);
	ufs_data_transfer_config(UFS_DATA_STOP);
	reg_value = readl(UFS_REG_CRYPTOCFG_0_16 + (uintptr_t)ufs_slot * 0x80);
	if ((reg_value >> 31) & 0x1) {
		/*
		 * step 1st
		 * Verify that no pending transactions reference x-CRYPTOCFG
		 * in their CCI field, i. e. UTRD.CCI != x for all pending
		 * transactions
		 *
		 * step 2nd writing 0x0 to clear x-CRYPTOCFG reg
		 */
		writel(0x0,
		       UFS_REG_CRYPTOCFG_0_16 + (uintptr_t)ufs_slot * 0x80);
	}
	/*
	 * step 3rd write the cryptographic key to x-CRYPTOKEY field
	 * The key is organized according to the algorithm-specific layout.
	 * Unused regions of CRYPTOKEY should be written with zeros.
	 * The key is written in little-endian format, sequentially
	 * and in one atomic set of operations. (set 4 bytes each time.)
	 */
	for (i = 0; i < CRYPTO_KEY_REG_NUM; i++) {
		key_reg_addr = UFS_REG_CRYPTOCFG_0_0 +
			       (uintptr_t)ufs_slot * 0x80 + (uintptr_t)i * 4;
		writel((*(UINT32 *)key + i), key_reg_addr);
	}

	/* step 4th set x-CRYPTOCFG with CAPIDX, DUSIZE, and CFGE=1 */
	writel(0x80000008, UFS_REG_CRYPTOCFG_0_16 + (uintptr_t)ufs_slot * 0x80);
	ufs_data_transfer_config(UFS_DATA_START);
	tloge("%s, config ckey to slot 0x%x exit\n", __func__, ufs_slot);

	return 0;
}

UINT32 file_encry_enable_kdf(void)
{
	tlogd("enable kdf in teeos driver\n");
	writel(0x1, UFS_REG_KEY_KDF_EN);
	return 0;
}
