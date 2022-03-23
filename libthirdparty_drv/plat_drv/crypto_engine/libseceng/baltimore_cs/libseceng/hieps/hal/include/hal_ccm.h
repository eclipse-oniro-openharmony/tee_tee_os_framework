/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hal-level-interface declaration for AES-CCM
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/07/22
 */
#ifndef __HAL_CCM_H__
#define __HAL_CCM_H__
#include <common_sce.h>

/*
 * ccm payload process param
 */
struct ccm_proc_param {
	u32        direction;
	const u8   *pkey;       /* pointer to key */
	u32        keylen;      /* byte length of key */
	u8         mac_iv[SYMM_IVLEN_AES];
	u8         cipher_iv[SYMM_IVLEN_AES];
	u32        payload_len; /* byte length of payload */
	u32        aadlen;      /* byte length of aad */
	u32        taglen;      /* byte length of tag */
	u32        nonce_len;
	u8         *pnonce;
};

struct ccm_payload_update {
	const u8          *pdin;
	u32               dinlen;
	u8                *pdout;
	u32               doutlen;
};

struct ccm_payload_dofinal {
	const u8          *pdin;
	u32               dinlen;
	u8                *pdout;
	u32               doutlen;
	u8                *ptag;
	u32               taglen;
};

err_bsp_t hal_ccm_payload_update(struct ccm_proc_param *pparam,
				 struct ccm_payload_update *pccm);

err_bsp_t hal_ccm_payload_dofinal(struct ccm_proc_param *pparam,
				  struct ccm_payload_dofinal *pccm);

#endif
