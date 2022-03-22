/**
 * @file   : hal_rsa.h
 * @brief  : RSA hal
 * @par    : Copyright(c) 2018-2034, HUAWEI Technology Co., Ltd.
 * @date   : 2018/01/05
 * @author : z00358830
 * @note   :rsa hal for cos
 */
#ifndef __HAL_RSA_H__
#define __HAL_RSA_H__
#include <common_rsa.h>

typedef struct hal_rsa_key_struct {
	u32     width;        /* key宽度 */
	u8        *pn;        /* 指向密钥模数的指针 */
	u8        *pe;        /* 指向公钥指数的指针 */
	u32        elen;        /* e的长度 */
	u8        *pd;        /* 指向私钥指数的指针 */
} hal_rsa_key_s;

typedef struct hal_rsa_crtkey_struct {
	u32     width;        /* key宽度 【p、q、dp、dq、qinv的宽度是width / 2】 */
	u8        *pn;        /* 指向密钥模数的指针 */
	u8        *pe;        /* 指向公钥指数的指针 */
	u32        elen;        /* e的长度 */
	u8        *pp;        /* 指向私钥p的指针 */
	u8        *pq;        /* 指向私钥q的指针 */
	u8        *pdp;        /* 指向私钥dp的指针 */
	u8        *pdq;        /* 指向私钥dq的指针 */
	u8        *pqinv;     /* 指向私钥qinv的指针 */
} hal_rsa_crtkey_s;

typedef struct hal_rsa_crypto_struct {
	hal_rsa_key_s       *pkey_s;
	const u8            *pdin;
	u8                  *pdout;
} hal_rsa_crypto_s;

typedef struct hal_rsa_crtcrypto_struct {
	hal_rsa_crtkey_s       *pcrtkey_s;
	const u8               *pdin;
	u8                     *pdout;
} hal_rsa_crtcrypto_s;

/**
 * @brief      : hal_rsa_gen_key
 * @param[out]  : pkey_s ,point to the struct hal_rsa_key_s
 * @return     : ::err_bsp_t error code
 * @note       : generate rsa standard key, input e ,output d n
 */
err_bsp_t hal_rsa_gen_key(hal_rsa_key_s *pkey_s);

/**
 * @brief      : hal_rsa_gen_crtkey
 * @param[in]  : pcrtkey_s point to rsa crt key struct hal_rsa_crtkey_s
 * @return     : ::err_bsp_t error code
 * @note       :generate rsa crt key (input e and width, output p q dp dq qinv)
 */
err_bsp_t hal_rsa_gen_crtkey(hal_rsa_crtkey_s *pcrtkey_s);

/**
 * @brief      : hal_rsa_calculate_pubkey
 * @param[in/out]  : pkey_s point to the struct hal_rsa_key_s
 * @return     : ::err_bsp_t
 * @note       :calculate pubkey
 */
err_bsp_t hal_rsa_calculate_pubkey(hal_rsa_key_s *pkey_s);

/**
 * @brief      : hal_rsa_calculate_pubcrtkey
 * @param[in/out]  : pcrtkey_s point to the struct hal_rsa_crtkey_s
 * @return     : ::err_bsp_t error code
 * @note       :calculate e , from p q dp dq qinv, n
 */
err_bsp_t hal_rsa_calculate_pubcrtkey(hal_rsa_crtkey_s *pcrtkey_s);

/**
 * @brief      : hal_rsa_encrypt
 * @param[in]  : pcrypto_s point to struct hal_rsa_crypto_s
 * @return     : ::err_bsp_t error code
 * @note       :rsa encrypt msg. input pdin ,pubkey , output pdout
 */
err_bsp_t hal_rsa_encrypt(const hal_rsa_crypto_s *pcrypto_s);

/**
 * @brief      : hal_rsa_decrypt
 * @param[in]  : pcrypto_s point to the struct hal_rsa_crypto_s
 * @return     : ::err_bsp_t error code
 * @note       :decrypt msg use rsa private key d n
 */
err_bsp_t  hal_rsa_decrypt (const hal_rsa_crypto_s *pcrypto_s);

/**
 * @brief      : hal_rsa_crt_decrypt
 * @param[in]  : pcrtcrypto_s point to the hal_rsa_crtcrypto_s
 * @return     : ::err_bsp_t
 * @note       :decrypt the msg with rsa crt key p q dp dq qinv
 */
err_bsp_t hal_rsa_crt_decrypt(const hal_rsa_crtcrypto_s *pcrtcrypto_s);

#endif /* end of __HAL_RSA_H__ */
