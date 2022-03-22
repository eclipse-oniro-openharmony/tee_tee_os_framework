/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ccdriver init defines
 * Create: 2020-06-18
 */
#ifndef CC_DRIVER_HAL_H
#define CC_DRIVER_HAL_H

#define CC_DRIVER_OK         0
#define INVALID_CTX_SIZE     0
#define INVALID_HASH_MODE    (-1)
#define MD5_LEN              16
#define SHA1_LEN             20
#define SHA224_LEN           28
#define SHA256_LEN           32
#define SHA384_LEN           48
#define SHA512_LEN           64
#define INVALID_HASH_LEN     0
#define INVALID_DRV_MODE     (-1)
#define INVALID_SALT_LEN     0U
#define INVALID_CURVE_ID     0U
#define INVALID_DOMAIN_ID    (-1)
#define ECC_160_KEY_SIZE     160
#define ECC_192_KEY_SIZE     192
#define ECC_224_KEY_SIZE     224
#define ECC_256_KEY_SIZE     256
#define ECC_384_KEY_SIZE     384
#define ECC_521_KEY_SIZE     521
#define ECC_INVALID_KEY_SIZE 0
#define ALIGNED_TO_WORD(size) (4 * (((size) + 3) / 4))
#define BITS_TO_BYTE(x) (((x) + 7) / 8)
#define BYTES_TO_WORD(x) (((x) + 3) / 4)
#define ADDR_OFFSET_ALIGNED(x) ((4 - ((x) & 3)) & 3)
#define ECC_POINT_TYPE      4
#define ECC_POINT_LENGTH    1
#define AES_KEY_16_BYTES    16
#define AES_KEY_24_BYTES    24
#define AES_KEY_32_BYTES    32
#define AES_KEY_64_BYTES    64
#define INVALID_KEY_SIZE_ID (-1)
#define INVALID_DATA_SIZE   0
#define DES_MAC_LEN         8
#define AES_BLOCK_SIZE      16
#define AES_CMAC_LEN        16
#define ONE_BYTE_MAX_VALUE  255
#define HALF_SIZE_BASE      2
#define ODD_NUM_MASK        1UL
#define HALF_WORD__LEN      16
#define BITS_LEN_ONE_BYTE   8
#define REVERSE_HALF_WORD(x) ((x) >> HALF_WORD__LEN | (x) << HALF_WORD__LEN)
#define REVERSE_ONE_WORD(x)  (((REVERSE_HALF_WORD((x)) & 0xff00ff00UL) >> BITS_LEN_ONE_BYTE) | \
    ((REVERSE_HALF_WORD((x)) & 0x00ff00ffUL) << BITS_LEN_ONE_BYTE))

struct alg_to_ctx_size_t {
    uint32_t alg_type;
    uint32_t ctx_size;
};

struct alg_to_salt_len_t {
    uint32_t alg_type;
    uint32_t salt_len;
};

#endif
