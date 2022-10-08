/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Create: 2019-05-29
 * Description: soft engine in boringssl
 */
#ifndef __CRYPTO_WRAPPER_H__
#define __CRYPTO_WRAPPER_H__

#include <stdint.h>
#include <tee_defines.h>
#include <chinadrm.h>
#include "crypto_aes_wrapper.h"
#include "crypto_cert_wrapper.h"
#include "crypto_ec_wrapper.h"
#include "crypto_ec_x509_wrapper.h"
#include "crypto_rsa_wrapper.h"
#include "crypto_x509_wrapper.h"
#include "crypto_inner_wrapper.h"

#define SHA256_LEN                   32
#define OEM_KEY_LEN                  16
#define ECC_P256_PRIV_LEN            64
#define ECC_P256_PUB_LEN             32
#define ATTEST_TBS_MAXSIZE           512
#define ATTESTATION_KEY_USAGE_OFFSET 16
#define EC_FIX_BUFFER_LEN            66
#define SHA256_HASH_LEN              32

/* macro in tomcrypto start */
/* ECC domain id */
#define NIST_P192                    0
#define NIST_P224                    1
#define NIST_P256                    2
#define NIST_P384                    3
#define NIST_P521                    4

#define SHA1_HASH                    1
#define SHA224_HASH                  2
#define SHA256_HASH                  3
#define SHA384_HASH                  4
#define SHA512_HASH                  5
/* Algorithm id */
#define RSA_ALG                      0
#define ECC_ALG                      1
/* macro in tomcrypto end */
#define DIR_ENC                      0
#define DIR_DEC                      1

#define CRYPTO_NUMBER_TWO            2
#define CRYPTO_NUMBER_THREE          3
#define CRYPTO_NUMBER_FOUR           4
#define CRYPTO_NUMBER_FIVE           5
#define CRYPTO_NUMBER_SIX            6
#define CRYPTO_NUMBER_SEVEN          7
#define CRYPTO_NUMBER_EIGHT          8
#define VALIDITY_TIME_SIZE           13
#define SECRET_KEY_MAX_LEN           64
#define CER_PUBLIC_KEY_MAX_LEN       300
#define VALIDITY_FIX_LEN             32
#define KEY_USAGE_FIX_LEN            41
#define ITEM_THREE_ADD_LEN           12
#define ITEM_THREE_MOVE_LEN          27
#define ITEM_TWO_ADD_LEN             23

/* table struct for match convert */
typedef struct {
    uint32_t src;
    uint32_t dest;
} crypto_u2u;

typedef struct {
    unsigned char *ou;
    unsigned char *o;
    unsigned char *c;
    unsigned char *cn;
} dn_name_t;

#endif
