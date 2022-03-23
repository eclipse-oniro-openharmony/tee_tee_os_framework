/**
 * @file   : hal_hmac.h
 * @brief  : support hmac-sha256
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2018/05/15
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __HAL_HMAC_H__
#define __HAL_HMAC_H__
#include <hal_hash.h>

typedef struct hal_hmac_ctx_struct {
	hal_hash_ctx_s  hash_ctx_ipad;  /**< used for ipad update */
	hal_hash_ctx_s  hash_ctx_opad;  /**< used for opad dofinal */
} hal_hmac_ctx_s;

/* multi-part hmac */
err_bsp_t hal_hmac_init(hal_hmac_ctx_s *pctx_s, u32 alg, const u8 *pkey, u32 keylen);
err_bsp_t hal_hmac_update(hal_hmac_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen);
err_bsp_t hal_hmac_dofinal(hal_hmac_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);

#endif
