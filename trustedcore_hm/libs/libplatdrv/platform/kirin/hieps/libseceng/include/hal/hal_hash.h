/**
 * @file   : hal_hash.h
 * @brief  : Hash Algorithm interface provided to COS
 *           Hash Algorithm supports SHA1, SHA256, indata length must be
 *           multiple of HASH_BLOCK_LEN, input data will not be pad in the interface
 *           all the indata is big-endian, length is byte length
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2017/12/15
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __HAL_HASH_H__
#define __HAL_HASH_H__
#include <common_symm.h>

typedef struct hal_hash_ctx_struct {
	u32    algorithm;                    /**< SHA1,SHA224,SHA256,SHA384,SHA512,SM3 */
	u32    blen;                         /**< unprocessed data length in buf */
	u32    tlen;                         /**< total length of user's data */
	u8     iv[SYMM_OUTLEN_HASH_MAX];     /**< ivout of data already processed */
	u8     buf[SYMM_BLKLEN_HASH_MAX];    /**< data unprocessed */
} hal_hash_ctx_s;

typedef struct hal_hash_struct {
	u32                  algorithm; /**< SHA1, SHA256, SM3 */
	pal_master_addr_t    pdin;      /**< pointer to indata */
	u32                  dinlen;    /**< indata length in Byte */
	const u8            *pivin;     /**< pointer to ivin */
	u8                  *pdout;     /**< pointer to outdata buf */
	u32                 *pdoutlen;  /**< in/out, in is outbuf len, out is real outdata length */
	u32                  padding_en;/**< SEC_ENABLE/SEC_DISABLE */
	u32                  tlen;      /**< total length in byte of hash data */
	u32                  transfer;  /**< cpu/master */
} hal_hash_s;

/**
 * @brief      : hal_hash_single
 *               cal hash in single-part
 * @param[in]  : alg, sha1, sha256, sm3
 * @param[in]  : pdin, pal_master_addr_t, must be aligned to sizeof(u32)
 * @param[in]  : dinlen, byte len
 * @param[in]  : pdout, pointer to outbuffer, must be aligned to sizeof(u32)
 * @param[in]  : pdoutlen, pointer to outlen, must be aligned to sizeof(u32)
 * @return     : error code
 */
err_bsp_t hal_hash_single(u32 alg, pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);

/* multi-part hash */
err_bsp_t hal_hash_init(hal_hash_ctx_s *pctx_s, u32 alg);

/**
 * @brief      : hal_hash_update
 *               hash update
 * @param[in]  : pctx_s, pointer to hah_hash_ctx_s
 * @param[in]  : pdin, pal_master_addr_t, must be aligned to sizeof(u32)
 * @param[in]  : dinlen, dinlen of indata, dinlen muste be multiple of sizeof(u32)
 * @return     : error code
 */
err_bsp_t hal_hash_update(hal_hash_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen);

/**
 * @brief      : hal_hash_dofinal
 *               pad and finish hash compute
 * @param[in]  : pctx_s pointer to hal_hash_ctx_s
 * @param[in]  : pdin, pal_master_addr_t, must be aligned to sizeof(u32)
 * @param[in]  : dinlen, dinlen of indata, need be multiple of sizeof(u32) if total length of update is not multiple of blklen
 * @param[out] : pdout pointer to user's output buffer
 * @param[io]  : pdoutlen, in is outbuffer length, out is real out length
 * @return     : error code
 */
err_bsp_t hal_hash_dofinal(hal_hash_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);

#endif /* end of __HAL_HASH_H__ */

