/**
 * @file   : hal_mac.h
 * @brief  : Cipher-Based Message Authentication Code(MAC) interface provided to COS
 *           C-MAC support AES-CMAC, AES-CBCMAC, DES-CBCMAC, SM4-CBCMAC
 *           for CBCMAC, indata must be multiple of algorithm specific block length, input data will not be pad in the interface
 *           for AES-CMAC, indata length can not be multiple of algorithm specific block length
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2017/12/15
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __HAL_MAC_H__
#define __HAL_MAC_H__
#include <common_symm.h>

#define HAL_MAC_OUTLEN_AES      (16)
#define HAL_MAC_OUTLEN_DES      (8)
#define HAL_MAC_OUTLEN_SM4      (16)

typedef struct hal_mac_struct {
	u32              algorithm; /**< AES, DES, SM4 */
	const u8        *pkey;      /**< pointer to user key */
	u32              width;     /**< key width in bit */
	u32              mode;      /**< AES-CMAC, CBC-MAC */
	pal_master_addr_t       pdin;      /**< master addr */
	u32              dinlen;    /**< indata length */
	u8              *pdout;     /**< pointer to outdata buf */
	u32             *pdoutlen;  /**< in/out, in is outbuf len, out is real outdata length */
	const u8        *pivin;     /**< pointer to input IV buf */
	u8              *pivout;    /**< pointer to output IV buf */
} hal_mac_s;

/**
 * @brief      : hal_mac
 * @param[in]  : pmac_s:
 *               pdin: pal_master_addr_t, this type must be aligned to sizeof(u32)
 * @return     : error code
 */
err_bsp_t hal_mac(const hal_mac_s *pmac_s);

#endif /* end of __HAL_MAC_H__ */

