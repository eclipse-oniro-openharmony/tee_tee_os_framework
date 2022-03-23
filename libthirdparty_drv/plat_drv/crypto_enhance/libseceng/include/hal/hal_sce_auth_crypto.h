/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Symmetric encryption and decryption algorithm,
 *              include CCM,GCM,GMAC
 * Author: l00249396, liuhailong5@huawei.com
 * Create: 2019-04-28
 */
#ifndef __HAL_SCE_AUTH_CRYPTO_H__
#define __HAL_SCE_AUTH_CRYPTO_H__
#include <common_symm.h>

struct hal_sce_auth_crypto {
	u32               algorithm; /* AES */
	const u8         *pkey;
	u32               width;     /* key width in bit */
	u32               mode;      /* CCM, GCM, GMAC */
	u32               direction; /* Encrypt, Decrypt */
	pal_master_addr_t pdin;      /* addr of indata, must be acpu addr */
	u32               dinlen;    /* indata length in Byte */
	pal_master_addr_t pdout;     /* addr of outdata, must be acpu addr */
	u32              *pdoutlen;  /* in/out, in is outbuf len, out is real outdata length */
	const u8         *pivin;     /* iv means nonce if mode=CCM */
	u32               ivinlen;
	u8               *ptag;      /* ptag is unused if mode=CCM */
	u32               taglen;
	u8               *paad;
	u32               aadlen;
};

/* support AES-CCM AES-GCM AES-GMAC */
err_bsp_t hal_sce_auth_crypto(const struct hal_sce_auth_crypto *pcrypto);

#endif /* end __HAL_SCE_AUTH_CRYPTO_H__ */

