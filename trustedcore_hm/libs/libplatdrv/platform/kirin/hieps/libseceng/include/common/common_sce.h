/**
 * @file   : common_sce.h
 * @brief  : common data provided for drv.c, hal.c, reg.c and external
 * @par    : Copyright (c) 2017-2019, HUAWEI Technology Co., Ltd.
 * @date   : 2018/01/09
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __COMMON_SCE_H__
#define __COMMON_SCE_H__
#include <common_def.h>
#include <common_utils.h>

typedef enum {
	SYMM_ALGORITHM_AES    = 0,
	SYMM_ALGORITHM_SM4    = 1,
	SYMM_ALGORITHM_DES    = 2,
	SYMM_ALGORITHM_CRYPTO = SYMM_ALGORITHM_DES,
	SYMM_ALGORITHM_HASH_START = 3,
	SYMM_ALGORITHM_SHA1   = SYMM_ALGORITHM_HASH_START,
	SYMM_ALGORITHM_MD5    = 4,
	SYMM_ALGORITHM_SHA256 = 5,
	SYMM_ALGORITHM_SM3    = 6,
	SYMM_ALGORITHM_SHA224 = 7,
	SYMM_ALGORITHM_SHA384 = 8,
	SYMM_ALGORITHM_SHA512 = 9,
	SYMM_ALGORITHM_HASH_END = SYMM_ALGORITHM_SHA512,
	SYMM_ALGORITHM_MAX,
	SYMM_ALGORITHM_UNKNOWN = SYMM_ALGORITHM_MAX
} symm_algorithm_e;

typedef enum {
	SYMM_WIDTH_64   = 64,
	SYMM_WIDTH_128  = 128,
	SYMM_WIDTH_160  = 160,
	SYMM_WIDTH_192  = 192,
	SYMM_WIDTH_224  = 224,
	SYMM_WIDTH_256  = 256,
	SYMM_WIDTH_384  = 384,
	SYMM_WIDTH_512  = 512,
	SYMM_WIDTH_1024 = 1024,
	SYMM_WIDTH_UNKNOWN,
} symm_width_e;

typedef enum {
	SYMM_MODE_ECB    = 0,
	SYMM_MODE_CBC    = 1,
	SYMM_MODE_CBCMAC = 2,
	SYMM_MODE_CMAC   = 3,
	SYMM_MODE_CTR    = 4,
	SYMM_MODE_XTS    = 5,
	SYMM_MODE_CCM    = 6,
	SYMM_MODE_GCM    = 7,
	SYMM_MODE_GMAC   = 8,
	SYMM_MODE_MAX,
	SYMM_MODE_UNKNOWN = SYMM_MODE_MAX
} symm_mode_e;

typedef enum {
	SYMM_DIRECTION_DECRYPT = 0,
	SYMM_DIRECTION_ENCRYPT = 1,
	SYMM_DIRECTION_MAX,
	SYMM_DIRECTION_UNKNOWN = SYMM_DIRECTION_MAX
} symm_direction_e;

/* blk inlen */
#define SYMM_BLKLEN_AES                        BIT2BYTE(SYMM_WIDTH_128)
#define SYMM_BLKLEN_SM4                        BIT2BYTE(SYMM_WIDTH_128)
#define SYMM_BLKLEN_DES                        BIT2BYTE(SYMM_WIDTH_64)
#define SYMM_BLKLEN_HASH                       BIT2BYTE(SYMM_WIDTH_512)
#define SYMM_BLKLEN_HASH_SHA512                BIT2BYTE(SYMM_WIDTH_1024)

/* ivlen */
#define SYMM_IVLEN_AES                          SYMM_BLKLEN_AES
#define SYMM_IVLEN_SM4                          SYMM_BLKLEN_SM4
#define SYMM_IVLEN_DES                          SYMM_BLKLEN_DES
#define SYMM_IVLEN_SHA1                         BIT2BYTE(SYMM_WIDTH_160)
#define SYMM_IVLEN_MD5                          BIT2BYTE(SYMM_WIDTH_128)
#define SYMM_IVLEN_SHA256                       BIT2BYTE(SYMM_WIDTH_256)
#define SYMM_IVLEN_SM3                          BIT2BYTE(SYMM_WIDTH_256)
#define SYMM_IVLEN_SHA224                       BIT2BYTE(SYMM_WIDTH_256)
#define SYMM_IVLEN_SHA384                       BIT2BYTE(SYMM_WIDTH_512)
#define SYMM_IVLEN_SHA512                       BIT2BYTE(SYMM_WIDTH_512)

/* outlen */
#define SYMM_OUTLEN_SHA1                        SYMM_IVLEN_SHA1
#define SYMM_OUTLEN_MD5                         SYMM_IVLEN_MD5
#define SYMM_OUTLEN_SHA256                      SYMM_IVLEN_SHA256
#define SYMM_OUTLEN_SM3                         SYMM_IVLEN_SM3
#define SYMM_OUTLEN_SHA224                      BIT2BYTE(SYMM_WIDTH_224)
#define SYMM_OUTLEN_SHA384                      BIT2BYTE(SYMM_WIDTH_384)
#define SYMM_OUTLEN_SHA512                      SYMM_IVLEN_SHA512

#define ALG_IS_AES(alg)                     (SYMM_ALGORITHM_AES    == (alg))
#define ALG_IS_DES(alg)                     (SYMM_ALGORITHM_DES    == (alg))
#define ALG_IS_SM4(alg)                     (SYMM_ALGORITHM_SM4    == (alg))
#define ALG_IS_SHA1(alg)                    (SYMM_ALGORITHM_SHA1   == (alg))
#define ALG_IS_SHA256(alg)                  (SYMM_ALGORITHM_SHA256 == (alg))
#define ALG_IS_SM3(alg)                     (SYMM_ALGORITHM_SM3    == (alg))
#define ALG_IS_MD5(alg)                     (SYMM_ALGORITHM_MD5    == (alg))
#define ALG_IS_SHA224(alg)                  (SYMM_ALGORITHM_SHA224 == (alg))
#define ALG_IS_SHA384(alg)                  (SYMM_ALGORITHM_SHA384 == (alg))
#define ALG_IS_SHA512(alg)                  (SYMM_ALGORITHM_SHA512 == (alg))

#define MODE_IS_ECB(mode)                   (SYMM_MODE_ECB    == (mode))
#define MODE_IS_CBC(mode)                   (SYMM_MODE_CBC    == (mode))
#define MODE_IS_CBCMAC(mode)                (SYMM_MODE_CBCMAC == (mode))
#define MODE_IS_CMAC(mode)                  (SYMM_MODE_CMAC   == (mode))
#define MODE_IS_CTR(mode)                   (SYMM_MODE_CTR    == (mode))
#define MODE_IS_XTS(mode)                   (SYMM_MODE_XTS    == (mode))
#define MODE_IS_CCM(mode)                   (SYMM_MODE_CCM    == (mode))
#define MODE_IS_GCM(mode)                   (SYMM_MODE_GCM    == (mode))
#define MODE_IS_GMAC(mode)                  (SYMM_MODE_GMAC   == (mode))
#define MODE_IS_AUTH_CRYPTO(mode) \
	((SYMM_MODE_CCM <= (mode)) && ((mode) <= SYMM_MODE_GMAC))

#define WIDTH_IS_64(width)                  (SYMM_WIDTH_64  == (width))
#define WIDTH_IS_128(width)                 (SYMM_WIDTH_128 == (width))
#define WIDTH_IS_192(width)                 (SYMM_WIDTH_192 == (width))
#define WIDTH_IS_256(width)                 (SYMM_WIDTH_256 == (width))
#define WIDTH_IS_512(width)                 (SYMM_WIDTH_512 == (width))

u32 symm_get_blklen(u32 alg);
u32 symm_get_ivlen(u32 alg);
u32 symm_get_doutlen(u32 alg, u32 mode, u32 dinlen);
const u8 *symm_get_hash_init_iv(u32 alg);

#endif /* end of __COMMON_SCE_H__ */
