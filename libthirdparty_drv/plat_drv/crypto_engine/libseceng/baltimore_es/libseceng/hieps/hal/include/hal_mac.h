/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hal-level interface declaration for MAC
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/07/25
 */
#ifndef __HAL_MAC_H__
#define __HAL_MAC_H__
#include <common_sce.h>
#include <hal_symm_common.h>

struct hal_mac {
	u32               strategy;
	u32               algorithm; /* ::symm_alg */
	u32               mode;      /* ::symm_mode */
	u32               keytype;   /* ::symm_ktype */
	const u8          *pkey;
	u32               keylen;    /* ::symm_klen */
	const u8          *pivin;
	u32               ivinlen;   /* ::symm_ivlen */
	struct data_addr  pdin;
	u32               dinlen;
	u8                *pdout;
	u32               doutlen;
	u8                *pivout;
	u32               ivoutlen;  /* ::symm_ivlen */
};

/*
 * support AES-CMAC, AES-CBCMAC, DES-CBCMAC, SM4-CBCMAC.
 * for AES-CMAC:dont support "update"
 */
err_bsp_t hal_mac_function(const struct hal_mac *pmac);

#endif
