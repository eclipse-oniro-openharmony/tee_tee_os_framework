/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: bm test for sce&km.
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/08/19
 */
#ifndef __HAL_SYMM_BM_H__
#define __HAL_SYMM_BM_H__
#include <pal_types.h>

struct hal_cipher_smmu {
	pal_master_addr_t pdin_va;
	pal_master_addr_t pdout_va;
	pal_master_addr_t pdin_pa;
	pal_master_addr_t pdout_pa;
	u32 dinlen;
	u32 doutlen;
	u32 is_sec;
};

err_bsp_t hal_symm_bm(void);

err_bsp_t hal_aes_smmu_bm(struct hal_cipher_smmu *pcipher);

#endif
