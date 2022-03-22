/**
 * @file   : api_hmac.h
 * @brief  : declare of hmac interface
 * @par    : Copyright (c) 2018-2018, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/20
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __API_HMAC_H__
#define __API_HMAC_H__

#include <hal_hmac.h>

typedef hal_hmac_ctx_s api_hmac_ctx_s;

typedef struct hmac_struct {
	u32               algorithm;
	u8                *pkey;
	u32               keylen;
	pal_master_addr_t pdin;
	u32               dinlen;
	u8               *pdout;
	u32              *pdoutlen;
} api_hmac_s;

/**
 * @brief      : api_hmac
 *               compute hmac in a single functiion.
 * @param[in]  : algorithm
 *               refer to hash algorithm used
 * @param[in]  : pkey
 *               a pointer to key.
 * @param[in]  : keylen
 *               the length in bytes of pkey.
 * @param[in]  : pdin
 *               a pointer to message.
 * @param[in]  : dinlen
 *               the length in bytes of pdin
 * @param[out] : pdout
 *               a pointer to buffer to hold hmac
 * @param[io]  : pdoutlen
 *               in: the length in bytes of out buffer
 *               out:
 * @return     : BSP_RET_OK if success, others if fail
 */
err_bsp_t api_hmac(api_hmac_s *phmac_s);

err_bsp_t api_hmac_init(api_hmac_ctx_s *pctx_s, u32 alg, const u8 *pkey, u32 keylen);

err_bsp_t api_hmac_update(api_hmac_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen);

err_bsp_t api_hmac_dofinal(api_hmac_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);

/**
 * @brief      : api_hmac_licence
 *               This function is used to compute HMAC-SHA1 of Licence
 * @param[in]  : pdin
 *               A pointer to licence data.
 * @param[in]  : dinlen
 *               The length in bytes of pdin param.
 * @param[in]  : pdout
 *               A pointer to buffer to hold licence HMAC.
 * @param[in]  : pdoutlen
 *               IN: A pointer to an U32 that refer to length in bytes of the caller buffer
 *               OUT: The resulting length in bytes.
 * @return     : BSP_RET_OK if sucessful, others if there was an error.
 */
err_bsp_t api_hmac_licence(pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);

#endif
