/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: hash algorithm interface for china DRM
 * Create     : 2019/11/04
 */

#ifndef __CDRMR_HASH_H__
#define __CDRMR_HASH_H__
#include <common_utils.h>
#include <cdrmr_common.h>

#define CDRMR_HASH_USER_CTX_LENGTH   64
struct cdrmr_hash_user_ctx {
	unsigned int buff[CDRMR_HASH_USER_CTX_LENGTH];
};

/*
 * @brief      : configure algorithm to the user context
 * @param[in]  : algo, algorithm
 * @param[in]  : puser_ctx, the user context
 * @return     : 0 if successful, others fail
 */
int cdrmr_crypto_hash_init(CDRMR_HASH_Algorithm algo,
			   struct cdrmr_hash_user_ctx *puser_ctx);

/*
 * @param[in]  : puser_ctx, the point of user context
 * @param[in]  : pdin, the point of input data
 * @param[in]  : dinlen, the length of input data
 * @return     : 0 if successful, others fail
 */
int cdrmr_crypto_hash_update(struct cdrmr_hash_user_ctx *puser_ctx,
			     unsigned char *pdin, unsigned int dinlen);

/*
 * @brief      : hash calculation of the last data
 * @param[in]  : puser_ctx, the point of user context
 * @param[in]  : pdout, the point of output data
 * @param[in]  : pdoutlen, the point of output data length
 * @return     : 0 if successful, others fail
 */
int cdrmr_crypto_hash_dofinal(struct cdrmr_hash_user_ctx *puser_ctx,
			      unsigned char *pdout, unsigned int *pdoutlen);
#endif

