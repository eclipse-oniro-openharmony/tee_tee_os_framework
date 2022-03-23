/**
 * @file   : hal_km.h
 * @brief  : KM interface provided to COS
 *           1) key Derive by HUK, POS/POS2 and TMK
 *           2) generate RGK key
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2017/12/15
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __HAL_KM_H__
#define __HAL_KM_H__
#include <common_symm.h>

typedef struct hal_km_rtl_encrypt_struct {
	const u8        *pdin;      /**< pointer to indata */
	u32              dinlen;    /**< indata length in Byte */
	u32              mode;      /**< ECB, CBC */
	u8              *pdout;     /**< pointer to 16-byte buf */
	u32             *pdoutlen;  /**< in/out, in is outbuf len, out is real outdata length */
} hal_km_rtl_encrypt_s;

typedef struct hal_km_derive_struct {
	u32              derivesrc; /**< KDR, GID */
	const u8        *pdin;      /**< pointer to indata */
	u32              dinlen;    /**< indata length in Byte */
	u8              *pdout;     /**< NULL:unread; OTHER: pointer to 16-byte buf */
} hal_km_derive_s;

typedef struct hal_km_crypto_struct {
	u32                algorithm; /**< AES,SM4 */
	u32                keysel;    /**< GID, CEK, POS, DeriveK */
	const u8          *pkey;      /**< pointer to CEK, when GID, it is not needed */
	u32                width;     /**< key width */
	u32                direction; /**< Encypt, Decrypt */
	u32                mode;      /**< ECB, CBC, CTR */
	pal_master_addr_t  pdin;      /**< pointer to indata, must be algined to sizeof(u32) */
	u32                dinlen;    /**< indata length in Byte */
	const u8          *pivin;     /**< pointer to input IV */
	u8                *pivout;    /**< pointer to output IV */
	pal_master_addr_t  pdout;     /**< pointer to outdata buf, must be algined to sizeof(u32) */
	u32               *pdoutlen;  /**< in/out, in is outbuf len, out is real outdata length */
} hal_km_crypto_s;

typedef struct hal_km_mac_struct {
	u32                algorithm; /**< AES,SM4 */
	u32                keysel;    /**< GID, CEK, POS  */
	const u8          *pkey;      /**< pointer to CEK, when GID, it is not needed */
	u32                mode;      /**< CMAC, CBC MAC */
	pal_master_addr_t  pdin;      /**< pointer to indata, must be algined to sizeof(u32) */
	u32                dinlen;    /**< indata length in Byte */
	const u8          *pivin;     /**< pointer to input IV */
	u8                *pivout;    /**< pointer to output IV */
	u8                *pdout;     /**< pointer to outdata buf */
	u32               *pdoutlen;  /**< in/out, in is outbuf len, out is real outdata length */
} hal_km_mac_s;

/**
 * @brief      : hal_km_rtl_encrypt
 *               encrypt indata by AES-RTL, support ECB/CBC
 *               only support multi-block length
 * @param[in]  : prtl_enc
 *               pointer to hal_km_rtl_encrypt_s
 * @return     : BSP_RET_OK if success, others fail
 */
err_bsp_t hal_km_rtl_encrypt(hal_km_rtl_encrypt_s *prtl_enc);

/**
 * @brief      : hal_km_rtl_decypt
 *               decrypt KDR using AES-RTL-ECB, KDR is input by cpu
 *               this  api is used for phoenix
 * @param[in]  : pkdr, pointer to kdr(256bit) or NULL
 * @return     : BSP_RET_OK if success, others fail
 */
err_bsp_t hal_km_rtl_decypt(u8 *pkdr);

/**
 * @brief      : hal_km_derive
 *               derive by AES_CMAC, derivesrc support KDR, GID
 *               result is readable
 * @param[in]  : pderive_s, pointer to hal_km_derive_s
 * @return     : BSP_RET_OK if success, others fail
 */
err_bsp_t hal_km_derive(const hal_km_derive_s *pderive_s);

/**
 * @brief      : hal_km_clear_derive_key
 *               clear derive key, include readable and unreadable key
 * @return     : BSP_RET_OK if success, others fail
 */
err_bsp_t hal_km_clear_derive_key(void);

/**
 * @brief      : hal_km_derive_ddrenck
 *               derive ddrenc key by AES-CMAC using KDR,
 *               result is send to DDRENC hardware-automaitcally
 * @param[in]  : pdin, pointer to indata
 * @param[in]  : dinlen, byte length of indata
 * @return     : BSP_RET_OK if success, others fail
 */
err_bsp_t hal_km_derive_ddrenck(const u8 *pdin, u32 dinlen);

/**
 * @brief      : hal_km_crypto
 *               encrypt or decrypt by GID/POS, support AES, SM4
 * @param[in]  : pcrypto_s
 * @return     : BSP_RET_OK if success, others fail
 */
err_bsp_t hal_km_crypto(const hal_km_crypto_s *pcrypto_s);

/**
 * @brief      : hal_km_mac
 *               compute mac by GID, CEK
 * @param[in]  : pmac_s, pointer to hal_km_mac_s
 * @return     : BSP_RET_OK if success, others fail
 */
err_bsp_t hal_km_mac(const hal_km_mac_s *pmac_s);

#endif /* end of __HAL_KM_H__ */

