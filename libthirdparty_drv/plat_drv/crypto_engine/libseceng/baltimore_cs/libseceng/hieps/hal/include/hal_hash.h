/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hal-level interface declaration for hash
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/07/25
 */
#ifndef __HAL_HASH_H__
#define __HAL_HASH_H__
#include <common_sce.h>
#include <hal_symm_common.h>

struct hal_hash {
	u32               algorithm;  /* ::symm_alg */
	const u8          *pivin;     /* pointer to IV */
	u32               ivinlen;    /* ::symm_ivlen */
	struct data_addr  pdin;       /* pointer to indata */
	u32               dinlen;     /* byte length of pdin */
	u8                *pdout;     /* outbuffer */
	u32               doutlen;    /* ::hash_outlen */
	u8                *pivout;    /* out buffer for IVOUT */
	u32               ivoutlen;   /* ::symm_ivlen */
	u32               padding_en; /* MUST be SEC_NO */
	u32               tlen;       /* hash total byte length */
};

/*
 * hash compute, only support multiple of blklen, dont support padding.
 * for single-part computing or the firt calling of multi-part computing,
 * you need give the correct init_iv according to algorithm protocal.
 * phoenix:support MD5/SHA1/SHA256/SM3.
 * baltimore:support SHA224/SHA384/SHA512 additionally.
 */
err_bsp_t hal_hash_function(const struct hal_hash *phash);

#endif
