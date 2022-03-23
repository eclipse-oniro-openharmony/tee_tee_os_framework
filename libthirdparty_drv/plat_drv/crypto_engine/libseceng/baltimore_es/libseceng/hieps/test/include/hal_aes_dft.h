/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: aes dft for smmu test.
 * Author: l00249396
 * Create: 2019/11/05
 */
#ifndef __HAL_AES_DFT_H__
#define __HAL_AES_DFT_H__
#include <pal_types.h>

struct hal_smmu_test {
	u32                 ip_idx;
	const u8            *pkey;
	u32                 keylen;
	const u8            *pivin;
	u32                 ivinlen;
	pal_master_addr_t   src;
	u32                 src_len;
	pal_master_addr_t   dest;
	u32                 dest_len;
};

/*
 * only support AES CBC ENCRYPT WIDTH128 MASTER.
 * for smmu test, support SCE1, SCE2.
 */
err_bsp_t hal_aes_smmu_test(const struct hal_smmu_test *smmu_test);

#endif

