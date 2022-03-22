/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: common func provided for drv.c, hal.c, reg.c and external
 * Author: z00293770
 * Create: 2019-12-02
 */

#include <cc_aes.h>
#include <cc_aes_defs.h>
#include <api_cipher.h>
#include <hieps_agent.h>
#include <tee_mem_mgmt_api.h>
#include <pal_log.h>
#include <pal_libc.h>
#include <sre_syscall.h>
#include <securec.h>

#define BSP_THIS_MODULE BSP_MODULE_SCE
#define ADDR_IS_ALIGNED_4_BYTES(addr) ((INTEGER(addr)) % 4 == 0)

/**
 * @brief      : symm_get_blklen
 *               get one block length according to alg
 * @param[in]  : symm crypto algorithm
 * @return     : one block length in byte
 */
u32 symm_get_blklen(u32 alg)
{
	u32 blklen = 0;

	switch (alg) {
	case SYMM_ALGORITHM_AES:
		blklen = SYMM_BLKLEN_AES;
		break;
	case SYMM_ALGORITHM_SM4:
		blklen = SYMM_BLKLEN_SM4;
		break;
	case SYMM_ALGORITHM_DES:
		blklen = SYMM_BLKLEN_DES;
		break;
	case SYMM_ALGORITHM_SHA1:
	case SYMM_ALGORITHM_MD5:
	case SYMM_ALGORITHM_SHA256:
	case SYMM_ALGORITHM_SM3:
	case SYMM_ALGORITHM_SHA224:
		blklen = SYMM_BLKLEN_HASH;
		break;
	case SYMM_ALGORITHM_SHA384:
	case SYMM_ALGORITHM_SHA512:
		blklen = SYMM_BLKLEN_HASH_SHA512;
		break;
	default:
		PAL_ERROR("unsupport alg = %d\n", alg);
		break;
	}

	return blklen;
}

/**
 * @brief      : symm_get_ivlen
 *               get iv length according to alg
 * @param[in]  : symm crypto algorithm
 * @return     : iv length in byte
 */
u32 symm_get_ivlen(u32 alg)
{
	const u32 ivlen_list[] = {
		SYMM_IVLEN_AES,
		SYMM_IVLEN_SM4,
		SYMM_IVLEN_DES,
		SYMM_IVLEN_SHA1,
		SYMM_IVLEN_MD5,
		SYMM_IVLEN_SHA256,
		SYMM_IVLEN_SM3,
		SYMM_IVLEN_SHA224,
		SYMM_IVLEN_SHA384,
		SYMM_IVLEN_SHA512,
	};

	if (alg < ARRAY_SIZE(ivlen_list))
		return ivlen_list[alg];

	PAL_ERROR("unsupport alg = %d\n", alg);
	return 0;
}

/**
 * @brief      : symm_get_doutlen
 *               get length of outdata
 * @param[in]  : alg hash algorithm
 * @param[in]  : mode of operation
 * @param[in]  : dinlen length of input data
 * @return     : byte length of outdata
 */
u32 symm_get_doutlen(u32 alg, u32 mode, u32 dinlen)
{
	u32 ivlen;
	const u32 hash_outlen[] = {
		SYMM_OUTLEN_SHA1,
		SYMM_OUTLEN_MD5,
		SYMM_OUTLEN_SHA256,
		SYMM_OUTLEN_SM3,
		SYMM_OUTLEN_SHA224,
		SYMM_OUTLEN_SHA384,
		SYMM_OUTLEN_SHA512,
	};

	if (SYMM_ALG_IS_HASH(alg))
		return hash_outlen[alg - SYMM_ALGORITHM_SHA1];

	/* when ctr, doutlen is same to dinlen */
	if (MODE_IS_CTR(mode) || MODE_IS_XTS(mode))
		return dinlen;

	ivlen = symm_get_ivlen(alg);
	if (ivlen == 0)
		return ivlen;

	/* when hash or mac, outlen is ivlen */
	if (MODE_IS_CMAC(mode) || MODE_IS_CBCMAC(mode))
		return ivlen;

	/* when ecb,cbc doutlen is round up by blklen */
	return ROUND_UP(dinlen, ivlen);
}

