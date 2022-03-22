/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hmac function api
 * Author: l00414685
 * Create: 2019-7-29
 */
#ifndef __HISEE_HMAC_H__
#define __HISEE_HMAC_H__

#include <hisee_hash.h>

#define HISEE_HMAC_USER_CTX_LENGTH 128
/*
 * user's hmac context struct, which shouled be passed by the user throughout
 * the whole hmac process
 */
struct hisee_hmac_user_ctx {
	u32 buff[HISEE_HMAC_USER_CTX_LENGTH];
};

/**
 * @brief     : Initializes hmac context which is used on the entire hmac
 *              operation. This function is the first step of multi-part hmac.
 * @param[in] : pctx     : store the hmac context.
 * @param[in] : alg_type : store hash algorithm, specifies the enum symm_alg
 *                         support SHA1/MD5/SHA256/SM3/SHA224/SHA384/SHA512
 * @param[in] : pkey     : pointer to user's key, if keys longer than block
 *                         length, should hashed keys using alg_type.
 * @param[in] : keylen   : byte length of user key.
 * @return    : BSP_RET_OK : succ, other: fail.
 */
err_bsp_t hisee_hmac_init(struct hisee_hmac_user_ctx *pctx, u32 alg_type,
			  u8 *pkey, u32 keylen);

/**
 * @brief     : Process a block of data to be hmaced, update the hmac context.
 *              This function may be called 0 times, 1 times or multiple times,
 *              after the hisee_hmac_init function.
 * @param[in] : pctx   : store the hmac context, that was previously initialized
 *                     : by hisee_hmac_init or updated by hisee_hmac_update.
 * @param[in] : pdin   : pointer the address of input data to be hmaced,
 * @param[in] : dinlen : the length of the input data, the unit is byte.
 * @return    : BSP_RET_OK : succ, other: fail.
 */
err_bsp_t hisee_hmac_update(struct hisee_hmac_user_ctx *pctx,
			    const u8 *pdin, u32 dinlen);

/**
 * @brief     : Compute and output the final message mac.
 *              This function is the last step of multi-part hash.
 * @param[in] : pctx   : store the hmac context, which is previously initialized
 *                     : by hisee_hmac_init or updated by hisee_hmac_update.
 * @param[in] : pdin   : pointer the address of input data to be hmaced,
 * @param[in] : dinlen : the length of the input data, the unit is byte.
 * @param[out]: pdout  : pointer the address of output buffer.
 * @param[i/o]: pdoutlen : in is outbuffer length, out is real out length,
 *                         the unit is byte.
 * @return    : BSP_RET_OK : succ, other: fail.
 */
err_bsp_t hisee_hmac_dofinal(struct hisee_hmac_user_ctx *pctx,
			     const u8 *pdin, u32 dinlen,
			     u8 *pdout, u32 *pdoutlen);

#endif /* __HISEE_HMAC_H__ */

