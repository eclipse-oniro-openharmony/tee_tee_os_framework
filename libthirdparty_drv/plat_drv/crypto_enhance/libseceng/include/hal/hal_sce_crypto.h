/**
 * @file   : hal_sce_crypto.h
 * @brief  : Symmetric encryption and decryption algorithm interface provided to COS,
 *           including AES, DES and SM4 Algorithm
 *           indata must be multiple of algorithm specific block length, input data will not be pad in the interface
 *           all the indata is big-endian, length is byte length except key length is bit-length
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2017/12/15
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __HAL_SCE_CRYPTO_H__
#define __HAL_SCE_CRYPTO_H__
#include <common_symm.h>

typedef struct hal_sce_crypto_struct {
	u32               algorithm;  /**< algorithm, such as AES, DES, SM4 */
	const u8          *pkey;      /**< pointer to user key */
	u32               width;      /**< key width in bit */
	u32               mode;       /**< algorithm mode, such as ECB, CBC, CTR */
	u32               direction;  /**< Encypt, Decrypt */
	pal_master_addr_t pdin;       /**< addr of indata, must be acpu addr */
	u32               dinlen;     /**< indata length in Byte */
	pal_master_addr_t pdout;      /**< addr of outdata, must be acpu addr */
	u32               *pdoutlen;  /**< in/out, in is outbuf len, out is real outdata length */
	const u8          *pivin;     /**< pointer to input IV buf */
	u8                *pivout;    /**< pointer to output IV buf */
} hal_sce_crypto_s;

/**
 * @brief      : hal_sce_crypto
 *               encrypt or decrypt indata, support AES,DES(3DES) and SM4
 *               indata must be multiple of block len
 *               pal_master_addr_t, this type must be aligned to sizeof(u32)
 *               pointer(include pkey, pivin, pivout, pdoutlen) must be aligned to sizeof(u32)
 * @param[in]  : pcrypto_s
 * @return     : error code
 */
err_bsp_t hal_sce_crypto(const hal_sce_crypto_s *pcrypto_s);

#endif /* end of__HAL_SCE_CRYPTO_H__ */

