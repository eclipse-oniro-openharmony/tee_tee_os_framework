/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hal-level interface declaration for cipher
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/07/25
 */
#ifndef __HAL_CIPHER_H__
#define __HAL_CIPHER_H__
#include <common_sce.h>
#include <hal_symm_common.h>

enum symm_smmu {
	SYMM_SMMU_READ_N_WRITE_N = 0,
	SYMM_SMMU_READ_N_WRITE_Y = 1,
	SYMM_SMMU_READ_Y_WRITE_N = 2,
	SYMM_SMMU_READ_Y_WRITE_Y = 3,
};

struct hal_cb_param {
	u64 srcva;
	u32 srclen;
};

typedef err_bsp_t (*cb_func)(void *param, struct hal_cb_param *hcp);

struct hal_out_cb {
	cb_func func;
	void *param;
};

struct hal_cipher {
	u32               strategy;    /* ::strategy */
	u32               smmu_en;     /* ::symm_smmu */
	u32               smmu_is_sec; /* smmu:SEC_YES/SEC_NO */
	u32               algorithm;   /* ::symm_alg */
	u32               mode;        /* ::symm_mode */
	u32               direction;   /* ::symm_direction */
	u32               keytype;     /* ::symm_ktype */
	const u8          *pkey;
	u32               keylen;      /* ::symm_klen */
	const u8          *pivin;
	u32               ivinlen;     /* ::symm_ivlen */
	struct data_addr  pdin;
	u32               dinlen;
	struct data_addr  pdout;
	u32               doutlen;
	u8                *pivout;
	u32               ivoutlen;    /* ::symm_ivlen */
	struct hal_out_cb ocb;         /* hook for output */
};

/*
 * init params of struct hal_cipher.
 * call this before hal_cipher_function
 */
void hal_cipher_init(struct hal_cipher *pcipher);

/*
 * AES/DES/SM4 encrypt/decrypt compute.
 * AES:support ECB/CBC/CTR/XTS;
 *     for ECB/CBC:dinlen MUST be multiple of blklen.
 *     for XTS:dont support "update" compute.
 * SM4:support ECB/CBC/CTR.
 *     for ECB/CBC:dinlen MUST be multiple of blklen.
 * DES:support ECB/CBC.
 *     for ECB/CBC:dinlen MUST be multiple of blklen.
 *
 * pdin/pdout:support cpu addr and master addr.
 * smmu_en:when SEC_ENABLE, pdin.type should be ADDR_TYPE_MASTER and
 * pdin.addr will be treated as VA, same as pdout.
 */
err_bsp_t hal_cipher_function(const struct hal_cipher *pcipher);

#endif
