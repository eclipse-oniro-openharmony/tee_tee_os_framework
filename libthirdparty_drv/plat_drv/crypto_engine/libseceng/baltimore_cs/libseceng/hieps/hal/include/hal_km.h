/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hal-level interface declaration for km function
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/07/25
 */
#ifndef __HAL_KM_H__
#define __HAL_KM_H__
#include <common_sce.h>

#define HAL_KM_DERIVE_OUTLEN_16  16
#define HAL_KM_DERIVE_OUTLEN_32  32
#define HAL_KM_DERIVE_OUTLEN_64  64

struct hal_derive {
	u32              keytype;  /* ::symm_ktype */
	u32              readable; /* SEC_YES/SEC_NO */
	const u8         *pdin;    /* pointer to derive vector */
	u32              dinlen;   /* byte length of pdin */
	u8               *pdout;   /* outbuf for derive key */
	u32              doutlen;  /* MUST be SYMM_KEYLEN_16 */
};

struct hal_rtl_encrypt {
	u32              mode;      /* support ECB, CBC */
	u32              dinlen;    /* byte length of pdin */
	const u8         *pdin;     /* pointer to input data */
	u8               *pdout;    /* pointer to output data */
	u32              *pdoutlen; /* pointer to output data length */
	u8               *pivin;    /* pointer to vector */
	u32              ivinlen;   /* length to vector */
};

/*
 * decrypt KDR/GID/POS by RTL. used for baltimore and later.
 * KDR/GID/POS is stored in efuse, KM hardware IP will read it.
 */
err_bsp_t hal_km_rtl_decrypt_function(void);
err_bsp_t hal_km_rtl_encrypt_function(struct hal_rtl_encrypt *rtl_encrypt);
/*
 * clear km derive key
 */
err_bsp_t hal_km_clear_derive_key(void);

/*
 * derive key by AES-CMAC
 * phoenix: support KDR/GID, only support readable key,
 *          outlen is fixed to SYMM_KEYLEN_16.
 * baltimore: support KDR/GID/POS.
 *            KDR:support readable and unreadable derive,
 *                outlen is fixed to 16-bytes(SYMM_KEYLEN_16),
 *                but you can call this function for four times in total,
 *                thus you can get 64-bytes(SYMM_KEYLEN_64) key.
 *            GID:only support readable, outlen is fixed to SYMM_KEYLEN_16.
 *            POS:only support unreadable, outlen is fixed to SYMM_KEYLEN_16.
 *
 *            for GID/POS derive, if you call this func more than one time,
 *            the previous key will be overwrite by the later key.
 */
err_bsp_t hal_km_derive_function(const struct hal_derive *pderive);

#endif
