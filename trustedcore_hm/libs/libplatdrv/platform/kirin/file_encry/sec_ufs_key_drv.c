/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: Library for FBE2
 * Author: security-ap
 * Create: 2018-06-11
 */

#include "sec_ufs_key_drv.h"

#include <sre_typedef.h>
#include <register_ops.h> // writel
#include <tee_log.h>

/*
 * set the key into the x-CRYPTOCFG of UFS controller.
 * return: 0 - success, 1 - some error occurs
 */
int ufs_kirin_uie_key_config(uint32_t key_index, uint8_t *key, uint32_t length)
{
	uint32_t reg_value;
	uintptr_t key_reg_addr;
	uint32_t i;

	if (key_index >= MAX_CRYPTO_KEY_INDEX || length != AES_DECKEY_LEN ||
	    !key) {
		tloge("ufs inline crypt key index is invalid.\n");
		return 1;
	}
	/*
	 * the key slot distance is 0x80.
	 * key operation start, check bit31
	 */
	reg_value = readl(UFS_REG_CRYPTOCFG_0_16 + (uintptr_t)key_index * 0x80);
	if ((reg_value >> 31) & 0x1) {
		/*
		 * step 1st
		 * Verify that no pending transactions reference x-CRYPTOCFG
		 * in their CCI field, i.e. UTRD.CCI != x for all pending
		 * transactions
		 *
		 * step 2nd writing 0x0 to clear x-CRYPTOCFG reg
		 */
		writel(0x0, UFS_REG_CRYPTOCFG_0_16 +
				(uintptr_t)key_index * 0x80);
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
				(uintptr_t)key_index * 0x80 +
				(uintptr_t)i * 4;
		writel(*((uint32_t *)key + i), key_reg_addr);
	}

	/* step 4th set x-CRYPTOCFG with CAPIDX, DUSIZE, and CFGE=1 */
	writel(0x80000108, UFS_REG_CRYPTOCFG_0_16 +
				(uintptr_t)key_index * 0x80);
	/* key operation end */
	return 0;
}

