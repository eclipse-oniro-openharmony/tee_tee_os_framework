/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hal-level-interface declaration for AES-GCM
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/07/22
 */
#ifndef __HAL_GCM_H__
#define __HAL_GCM_H__
#include <common_sce.h>

struct gcm_iv_init {
	const u8        *pkey;
	u32             keylen;
	const u8        *pivin;
	u32             ivinlen;
	u8              *pivout;
	u32             ivoutlen;
};

struct gcm_aad_ghash {
	u32             is_gmac;  /* SEC_YES/SEC_NO */
	const u8        *pkey;
	u32             keylen;
	const u8        *pivin;   /* J0, only gmac need this */
	u32             ivinlen;
	const u8        *paad;
	u32             aadlen;
	u8              *pghash;  /* ghash or gmac */
	u32             ghashlen;
};

/*
 * gcm payload process param
 */
struct gcm_proc_param {
	u32             direction;
	const u8        *pkey;
	u32             keylen;
	u32             aadlen;
	u8              gctr_iv[SYMM_IVLEN_AES];
	u8              ghash[SYMM_IVLEN_AES];
};

struct gcm_payload_update {
	const u8        *pdin;
	u32             dinlen;
	u8              *pdout;
	u32             doutlen;
};

struct gcm_payload_dofinal {
	const u8        *pdin;
	u32             dinlen;
	u8              *pdout;
	u32             doutlen;
	u8              *ptag;
	u32             taglen;
};

/*
 * compute J0 by hardware.
 * if special IV(12bytes), dont call this.
 */
err_bsp_t hal_gcm_iv_init(struct gcm_iv_init *pgcm);

/*
 * compute aad ghash, hardware do padding(0x00).
 * it also support gmac.
 */
err_bsp_t hal_gcm_aad_ghash(struct gcm_aad_ghash *pgcm);

err_bsp_t hal_gcm_payload_update(struct gcm_proc_param *pparam,
				 struct gcm_payload_update *pgcm);

err_bsp_t hal_gcm_payload_dofinal(struct gcm_proc_param *pparam,
				  struct gcm_payload_dofinal *pgcm);

#endif
