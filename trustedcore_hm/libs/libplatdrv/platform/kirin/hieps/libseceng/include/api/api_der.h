/**
 * @file   : api_der.h
 * @brief  : declare of utils
 * @par    : Copyright (c) 2018-2018, HUAWEI Technology Co., Ltd.
 * @date   : 2018/01/11
 * @author : z00293770
 */
#ifndef __API_DER_H__
#define __API_DER_H__
#include <sec_plat.h>

typedef struct rsa_derkey_struct {
	u32    width;        /* key宽度 */
	u32    elen;        /* e的长度 */
	u8    *pe;        /* 指向公钥指数的指针 */
	u8    *pn;        /* 指向密钥模数的指针 */
	u8    *pd;        /* 指向私钥指数的指针 */
	u8    *pcrt;        /* 指向私钥指数的指针 */
} rsa_derkey_s;

/**
 * @brief      : der_decode
 *               decode rsa key from der data.
 * @param[in]  : pderdata
 *                   A pointer to der data.
 * @param[out] : pkey
 *                   key decoded from der data.
 * @return     : BSP_RET_OK if successful, others if fail.
 */
err_bsp_t der_decode(u8 *pderdata, u32 der_size, rsa_derkey_s *pkey);

/**
 * @brief      : der_encode
 *               encode rsa key to der data.
 * @param[out]  : pderdata
 *                   A pointer to der data.
 * @param[in] : pkey
 *                   key data.
 * @param[out]  : der_size
 *                   der data length in byte.
 * @return     : BSP_RET_OK if successful, others if fail.
 */
err_bsp_t der_encode(rsa_derkey_s *pkey, u8 *pderdata, u32 *der_size);

#endif /* __API_DER_H__ */
