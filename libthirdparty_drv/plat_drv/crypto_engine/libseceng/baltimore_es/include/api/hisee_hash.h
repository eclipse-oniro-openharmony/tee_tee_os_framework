/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hash function api
 * Author: l00414685
 * Create: 2019-7-29
 */
#ifndef __HISEE_HASH_H__
#define __HISEE_HASH_H__

#include <pal_errno.h>
#include <common_sce.h>

#define HISEE_HASH_USER_CTX_LENGTH 64
/*
 * user's hash context struct, which shouled be passed by the user throughout
 * the whole hash process
 */
struct hisee_hash_user_ctx {
	u32 buff[HISEE_HASH_USER_CTX_LENGTH];
};

/**
 * @brief     : Initializes hash context which is used on the entire hash
 *              operation. This function is the first step of multi-part hash.
 * @param[in] : pctx     : store the hash context
 * @param[in] : alg_type : store hash algorithm, specifies the enum symm_alg
 *                         support SHA1/MD5/SHA256/SM3/SHA224/SHA384/SHA512
 * @return    : BSP_RET_OK : succ, other: fail
 */
err_bsp_t hisee_hash_init(struct hisee_hash_user_ctx *pctx, u32 alg_type);

/**
 * @brief     : Process a block of data to be hashed, update the hash context.
 *              This function may be called 0 times, 1 times or multiple times,
 *              after the hisee_hash_init function.
 * @param[in] : pctx   : store the hash context, that was previously initialized
 *                     : by hisee_hash_init or updated by hisee_hash_update.
 * @param[in] : pdin   : pointer the address of input data to be hashed,
 * @param[in] : dinlen : the length of the input data, the unit is byte.
 * @return    : BSP_RET_OK : succ, other: fail.
 */
err_bsp_t hisee_hash_update(struct hisee_hash_user_ctx *pctx,
			    const u8 *pdin, u32 dinlen);

/**
 * @brief     : Pad the input data, compute and output the final message digest.
 *              This function is the last step of multi-part hash.
 * @param[in] : pctx   : store the hash context, which is previously initialized
 *                     : by hisee_hash_init or updated by hisee_hash_update.
 * @param[in] : pdin   : pointer the address of input data to be hashed,
 * @param[in] : dinlen : the length of the input data, the unit is byte.
 * @param[out]: pdout  : pointer the address of output buffer.
 * @param[i/o]: pdoutlen : in is outbuffer length, out is real out length,
 *                         the unit is byte.
 * @return    : BSP_RET_OK : succ, other: fail.
 */
err_bsp_t hisee_hash_dofinal(struct hisee_hash_user_ctx *pctx,
			     const u8 *pdin, u32 dinlen,
			     u8 *pdout, u32 *pdoutlen);

/**
 * @brief     : This function process a single buffer od data.
 * @param[in] : alg      : store hash algorithm, specifies the enum symm_alg
 *                         support SHA1/MD5/SHA256/SM3/SHA224/SHA384/SHA512.
 * @param[in] : pdin   : pointer the address of input data to be hashed.
 * @param[in] : dinlen : the length of the input data, the unit is byte.
 * @param[out]: pdout  : pointer the address of output buffer.
 * @param[i/o]: pdoutlen : in is outbuffer length, out is real out length,
 *                         the unit is byte.
 * @return    : BSP_RET_OK : succ, other: fail
 */
err_bsp_t hisee_hash_single(u32 alg, const u8 *pdin, u32 dinlen,
			    u8 *pdout, u32 *pdoutlen);

#endif /* __HISEE_HASH_H__ */
