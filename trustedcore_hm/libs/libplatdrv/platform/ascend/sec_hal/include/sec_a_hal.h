/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
* Description: definition of data type
* Author: shenhan
* Create: 2020/03/30
*/
#ifndef __SEC_A_HAL_H__
#define __SEC_A_HAL_H__

#include <stdint.h>
#include "sec_api.h"
#include "trng_api.h"

#ifndef NULL
#define NULL                                                (void *)0
#endif

#define SHIFT2                                              2
#define SHIFT3                                              3
#define SHIFT4                                              4
#define SHIFT29                                             29
#define SHIFT0                                              0
#define SHIFT7                                              7
#define SHIFT8                                              8
#define SHIFT16                                             16
#define SHIFT24                                             24

#define W2B_SIZE                                            4
#define W2B_OFF0                                            0
#define W2B_OFF1                                            1
#define W2B_OFF2                                            2
#define W2B_OFF3                                            3
#define BYTE_MASK                                           0xFF

#define AES_CTR_COUNTER_ADD                                 8
#define AES_CTR_COUNTER_OFFSET                              12

#define BYTE2WORD_MASK                                      0x3

#define IS_FIRST_BLOCK                                      0x1
#define IS_NOT_FIRST_BLOCK                                  0x0

#define SHA1_OUT_WLEN                                       5
#define SHA224_OUT_WLEN                                     7
#define SHA256_OUT_WLEN                                     8
#define SHA384_OUT_WLEN                                     12
#define SHA512_OUT_WLEN                                     16
#define SM3_OUT_WLEN                                        8

#define CIPHER_BD_SIZE                                      0x80

#define SHA_BLOCK_LEN                                       0x80
#define SHA_IV_LEN                                          0x40
#define SHA_LEN_WLEN                                        2
#define SHA_KEY_MAX_BLEN                                    0x80
#define SHA_BLOCK_LEN_MASK                                  0x0000007F

#define CIPHER_BLOCK_LEN                                    0x80
#define CIPHER_IV_LEN                                       0x10
#define CIPHER_KEY_MAX_LEN                                  0x20
#define CIPHER_BLOCK_LEN_MASK                               0x0000000F
#define CIPHER_UNIT_LEN                                     0x10

#define AE_BLOCK_LEN                                        0x80
#define AE_IV_LEN                                           0x10
#define AE_TAG_LEN                                          0x10
#define AE_KEY_MAX_LEN                                      0x20
#define AE_AAD_MAX_LEN                                      0x20
#define AE_BLOCK_LEN_MASK                                   0x0000000F
#define AE_NONCE_LEN                                        12

#define IV_LAST_WORD_BYTE0                                  12
#define IV_LAST_WORD_BYTE1                                  13
#define IV_LAST_WORD_BYTE2                                  14
#define IV_LAST_WORD_BYTE3                                  15

#define DERIVE_KEY_DEFAULT_ITR                              10000
#define DERIVE_KEY_MIN_ITR                                  1000
#define DERIVE_KEY_MAX_OUT                                  64
#define DERIVE_SALT_MAX_IN                                  256

#define ROOT_KEY_SIZE                                       32

#define RPMB_WRAPPING_KEY_SIZE                              80
#define RPMB_KEY_SIZE                                       32
#define BLOCK_LEN_MASK                                      0xFFFFFF80

#define PKCS5_PADDING                                        20
#define NOT_NEED_PADDING                                     21
#define NO_PADDING                                           22
#define CIPHER_BLOCK_BLEN                                    16
#define AES_MASK_BLEN                                        0XF
#define AAD_MAX_LEN                                          64

#define SEC_PAGE_SIZE                                       (16 * 1024)

typedef struct {
    uint32_t          alg_type;
    uint32_t          option;
    uint32_t          out_wlen;
} hash_option_map_s;

typedef struct {
    uint32_t          alg_type;
    uint32_t          option;
    uint32_t          out_wlen;
} hmac_option_map_s;

typedef struct {
    uint32_t          alg_type;
    uint32_t          option;
    uint32_t          mode;
    uint32_t          padding_mode;
} cipher_option_map_s;

typedef struct {
    uint32_t          alg_type;
    uint32_t          ctx_size;
} ctx_size_map_s;

typedef struct {
    uint8_t           buf[SHA_BLOCK_LEN];
    uint8_t           iv[SHA_IV_LEN];
    uint8_t           data_out_buf[SHA_BLOCK_LEN];
    /* store alg id */
    uint32_t          alg_type;
    uint32_t          outlen;
    uint32_t          buf_offset;
    /* present hardware the first time */
    uint32_t          flag;
    /* store total len */
    uint32_t          total_len[SHA_LEN_WLEN];
} hash_ctx_t;

typedef struct {
    uint8_t           buf[SHA_BLOCK_LEN];
    uint8_t           iv[SHA_IV_LEN];
    uint8_t           data_out_buf[SHA_BLOCK_LEN];
    /* store alg id */
    uint8_t           c_key[SHA_KEY_MAX_BLEN];
    uint32_t          key_size;
    /* store alg id */
    uint32_t          alg_type;
    uint32_t          key_type;
    uint32_t          outlen;
    uint32_t          buf_offset;
    /* present hardware the first time */
    uint32_t          flag;
    /* store total len */
    uint32_t          total_len[SHA_LEN_WLEN];
} hmac_ctx_t;

typedef struct {
    uint8_t           buf[CIPHER_BLOCK_LEN + CIPHER_UNIT_LEN];
    uint8_t           buf2[CIPHER_BLOCK_LEN];
    uint8_t           iv[CIPHER_IV_LEN];
    /* store key */
    uint8_t           c_key[CIPHER_KEY_MAX_LEN];
    uint32_t          key_size;
    /* store var  */
    uint32_t          option;
    uint32_t          mode;
    uint32_t          direct;
    uint32_t          buf_offset;
    uint32_t          padding_mode;
} cipher_ctx_t;

typedef struct {
    uint8_t           auth_iv[AE_IV_LEN + AE_IV_LEN + AE_IV_LEN];
    uint8_t           cipher_iv[AE_IV_LEN];
    /* store key */
    uint8_t           c_key[AE_KEY_MAX_LEN];
    /* store var  */
    uint8_t           buf[AE_BLOCK_LEN];
    uint8_t           buf2[AE_BLOCK_LEN];
    uint32_t          key_size;
    uint32_t          buf_offset;
    uint32_t          tag_size;
    uint32_t          aad_size;
    uint32_t          mode;
    uint32_t          direct;
    uint32_t          total_data_size;
} ae_ctx_t;

typedef struct {
    uint8_t           derive_salt[DERIVE_SALT_MAX_IN];
    uint8_t           derive_key[DERIVE_KEY_MAX_OUT];
    uint32_t          salt_len;
    uint32_t          key_len;
} __attribute__((aligned(256))) derive_key_ctx_t;

typedef struct {
    uint8_t           bd[CIPHER_BD_SIZE];
} __attribute__((aligned(128))) sec_bd_t;

extern void *malloc_coherent(size_t n);
#endif
