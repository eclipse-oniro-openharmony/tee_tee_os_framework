/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: common data provided for drv.c, hal.c, reg.c and external
 * Author     : secengliu
 * Create     : 2018/01/09
 */
#ifndef __COMMON_SCE_H__
#define __COMMON_SCE_H__
#include <common_km.h>

enum symm_alg {
	/* cipher */
	SYMM_ALGORITHM_AES = 0,
	SYMM_ALGORITHM_SM4,
	SYMM_ALGORITHM_DES,
	SYMM_ALGORITHM_CRYPTO = SYMM_ALGORITHM_DES,
	/* hash */
	SYMM_ALGORITHM_SHA1,
	SYMM_ALGORITHM_MD5,
	SYMM_ALGORITHM_SHA256,
	SYMM_ALGORITHM_SM3,
	SYMM_ALGORITHM_SHA224,
	SYMM_ALGORITHM_SHA384,
	SYMM_ALGORITHM_SHA512,

	SYMM_ALGORITHM_MAX,

	SYMM_ALGORITHM_BYPASS = 0x7FFFFFFF
};

enum symm_klen {
	SYMM_KEYLEN_8  = 8,
	SYMM_KEYLEN_16 = 16,
	SYMM_KEYLEN_24 = 24,
	SYMM_KEYLEN_32 = 32,
	SYMM_KEYLEN_64 = 64,

	SYMM_KEYLEN_MAX,

	SYMM_KEYLEN_BYPASS = 0x7FFFFFFF
};

enum symm_mode {
	SYMM_MODE_ECB    = 0,
	SYMM_MODE_CBC    = 1,
	SYMM_MODE_CBCMAC = 2,
	SYMM_MODE_CMAC   = 3,
	SYMM_MODE_CTR    = 4,
	SYMM_MODE_XTS    = 5,

	SYMM_MODE_MAX,

	SYMM_MODE_BYPASS = 0x7FFFFFFF
};

enum symm_direction {
	SYMM_DIRECTION_DECRYPT = 0,
	SYMM_DIRECTION_ENCRYPT = 1,

	SYMM_DIRECTION_MAX,

	SYMM_DIRECTION_BYPASS  = 0x7FFFFFFF
};

/* blk inlen */
enum symm_blklen {
	/* cipher */
	SYMM_BLKLEN_DES         = 8,
	SYMM_BLKLEN_AES         = 16,
	SYMM_BLKLEN_SM4         = 16,
	/* hash */
	SYMM_BLKLEN_HASH        = 64, /* MD5/SHA1/SHA224/SHA256/SM3 */
	SYMM_BLKLEN_HASH_SHA512 = 128, /* SHA384/SHA512 */

	SYMM_BLKLEN_UNKNOWN     = 0x7FFFFFFF,
};

/* ivlen */
enum symm_ivlen {
	/* cipher */
	SYMM_IVLEN_DES     = SYMM_BLKLEN_DES,
	SYMM_IVLEN_AES     = SYMM_BLKLEN_AES,
	SYMM_IVLEN_SM4     = SYMM_BLKLEN_SM4,
	/* hash */
	SYMM_IVLEN_MD5     = 16,
	SYMM_IVLEN_SHA1    = 20,
	SYMM_IVLEN_SHA256  = 32,
	SYMM_IVLEN_SM3     = 32,
	SYMM_IVLEN_SHA224  = 32,
	SYMM_IVLEN_SHA384  = 64,
	SYMM_IVLEN_SHA512  = 64,

	SYMM_IVLEN_UNKNOWN = 0x7FFFFFFF,
};

/* hash outlen */
enum hash_outlen {
	SYMM_OUTLEN_MD5     = SYMM_IVLEN_MD5,
	SYMM_OUTLEN_SHA1    = SYMM_IVLEN_SHA1,
	SYMM_OUTLEN_SHA256  = SYMM_IVLEN_SHA256,
	SYMM_OUTLEN_SM3     = SYMM_IVLEN_SM3,
	SYMM_OUTLEN_SHA224  = 28,
	SYMM_OUTLEN_SHA384  = 48,
	SYMM_OUTLEN_SHA512  = SYMM_IVLEN_SHA512,

	SYMM_OUTLEN_UNKNOWN = 0x7FFFFFFF,
};
/* symm algorithm padding mode */
enum padding_type {
	SYMM_PADDING_NONE       = 0, /* No pad */
	SYMM_PADDING_PKCS7      = 1, /* pad value of pad_len */
	SYMM_PADDING_ISO9797_M1 = 2, /* pad 0000...00 */
	SYMM_PADDING_ISO9797_M2 = 3, /* pad 8000...00 */

	SYMM_PADDING_MAX,
};

#define SYMM_BLKLEN_HASH_MAX              SYMM_BLKLEN_HASH_SHA512
#define SYMM_OUTLEN_HASH_MAX              SYMM_OUTLEN_SHA512

#define ALG_IS_AES(alg)      ((alg)  == SYMM_ALGORITHM_AES)
#define ALG_IS_DES(alg)      ((alg)  == SYMM_ALGORITHM_DES)
#define ALG_IS_SM4(alg)      ((alg)  == SYMM_ALGORITHM_SM4)
#define ALG_IS_SHA1(alg)     ((alg)  == SYMM_ALGORITHM_SHA1)
#define ALG_IS_SHA256(alg)   ((alg)  == SYMM_ALGORITHM_SHA256)
#define ALG_IS_SM3(alg)      ((alg)  == SYMM_ALGORITHM_SM3)
#define ALG_IS_MD5(alg)      ((alg)  == SYMM_ALGORITHM_MD5)
#define ALG_IS_SHA224(alg)   ((alg)  == SYMM_ALGORITHM_SHA224)
#define ALG_IS_SHA384(alg)   ((alg)  == SYMM_ALGORITHM_SHA384)
#define ALG_IS_SHA512(alg)   ((alg)  == SYMM_ALGORITHM_SHA512)

#define ALG_IS_CIPHER(alg)   ((alg) <= SYMM_ALGORITHM_DES)
#define ALG_IS_HASH(alg)     (((alg) >= SYMM_ALGORITHM_SHA1) && \
			      (alg) <=  SYMM_ALGORITHM_SHA512)

#define MODE_IS_ECB(mode)    ((mode) == SYMM_MODE_ECB)
#define MODE_IS_CBC(mode)    ((mode) == SYMM_MODE_CBC)
#define MODE_IS_CBCMAC(mode) ((mode) == SYMM_MODE_CBCMAC)
#define MODE_IS_CMAC(mode)   ((mode) == SYMM_MODE_CMAC)
#define MODE_IS_CTR(mode)    ((mode) == SYMM_MODE_CTR)
#define MODE_IS_XTS(mode)    ((mode) == SYMM_MODE_XTS)

#endif /* end of __COMMON_SCE_H__ */
