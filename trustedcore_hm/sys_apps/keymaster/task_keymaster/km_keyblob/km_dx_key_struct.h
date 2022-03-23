/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster old dx key types
 * Create: 2020-08-21
 */

#ifndef __KM_DX_KEY_STRUCT_H
#define __KM_DX_KEY_STRUCT_H
#ifndef IV_LEN
#define IV_LEN               16
#endif
#define BITS_TO_BYTE 8
#define BITS_TO_INT	32
#define MAX_KEY_BUFFER_LEN 4096
/* suit dx CRYS_ECPKI_ORDER_MAX_LENGTH_IN_WORDS */
#define DX_EC_KEY_MODULE_MAX_LENGTH_IN_WORDS 18
/* suit dx CRYS_ECPKI_ORDER_MAX_LENGTH_IN_WORDS */
#define DX_EC_KEY_ORDER_MAX_LENGTH_IN_WORDS  19
/* suit dx  CRYS_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS */
#define DX_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS 5
/* suit dx CRYS_PKA_PUB_KEY_BUFF_SIZE_IN_WORDS */
#define DX_PKA_PUB_KEY_BUFF_SIZE_IN_WORDS 10
/* suit dx CRYS_PKA_PRIV_KEY_BUFF_SIZE_IN_WORDS */
#define DX_PKA_PRI_KEY_BUFF_SIZE_IN_WORDS 10
/* suit define CALC_FULL_BYTES */
#define bit_to_byte_size(num) (((num) + 7) >> 3)
/* suit dx SW_CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS */
#define DX_MAX_RSA_KEY_SIZE_IN_BIT 3072
/* suit dx CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS */
#define DX_RSA_MAX_IMUM_MOD_BUFFER_SIZE_IN_WORDS ((DX_MAX_RSA_KEY_SIZE_IN_BIT + 64UL) / 32)

#define KM_INVALID_VALUE 0xFFFFFFFF
/* sizeof(int32_t + sizeof(uint32_t)) */
#define KM_TLV_HEAD_LEN   8

/* suit dx CRYS_ECPKI_DomainID_t */
enum DX_EC_DOMAIN_ID {
    /* For prime field */
    DX_EC_DOMAIN_ID_SECP160K1,
    DX_EC_DOMAIN_ID_SECP160R1,
    DX_EC_DOMAIN_ID_SECP160R2,
    DX_EC_DOMAIN_ID_SECP192K1,
    DX_EC_DOMAIN_ID_SECP192R1,
    DX_EC_DOMAIN_ID_SECP224K1,
    DX_EC_DOMAIN_ID_SECP224R1,
    DX_EC_DOMAIN_ID_SECP256K1,
    DX_EC_DOMAIN_ID_SECP256R1,
    DX_EC_DOMAIN_ID_SECP384R1,
    DX_EC_DOMAIN_ID_SECP521R1,
    DX_EC_DOMAIN_ID_OFF_MODE,
    CRYS_ECPKI_DOMAIN_ID_LAST = 0x7FFFFFFF,
};

/* suit dx struct CRYS_ECPKI_PublKey_t */
struct dx_ecc_pub_key {
    uint32_t x[DX_EC_KEY_MODULE_MAX_LENGTH_IN_WORDS];
    uint32_t y[DX_EC_KEY_MODULE_MAX_LENGTH_IN_WORDS];
    enum DX_EC_DOMAIN_ID domain_id;
    uint32_t crys_pub_int_buff[DX_PKA_PUB_KEY_BUFF_SIZE_IN_WORDS];
};

/* suit dx struct CRYS_ECPKI_UserPublKey_t */
struct dx_ecc_user_pub_key {
    uint32_t valid_tag;
    uint32_t pub_key[(sizeof(struct dx_ecc_pub_key) + KM_NUM_BYTES_3) / KM_UINT32_BYTES];
};

/* suit dx struct CRYS_ECPKI_PrivKey_t */
struct dx_ecc_pri_key {
    uint32_t pri_key[DX_EC_KEY_MODULE_MAX_LENGTH_IN_WORDS + 1];
    enum DX_EC_DOMAIN_ID domain_id;
    uint32_t crys_pri_int_buff[DX_PKA_PRI_KEY_BUFF_SIZE_IN_WORDS];
};

/* suit dx struct CRYS_ECPKI_UserPrivKey_t */
struct dx_ecc_user_pri_key {
    uint32_t valid_tag;
    uint32_t pri_key[(sizeof(struct dx_ecc_pri_key) + KM_NUM_BYTES_3) / KM_UINT32_BYTES];
};

/* suit dx CRYS_RSA_DecryptionMode_t */
enum DX_RSA_DECRYPTO_MODE {
    DX_RSA_NOCRT = 10,
    DX_RSA_CRT   = 11,
    DX_RSA_DECRYPTO_NUM_OPTIONS,
    DX_RSA_DECRYPTO_MODE_LAST = 0x7FFFFFFF,
};

/* suit dx CRYS_RSA_KeySource_t */
enum DX_RSA_KEY_SOURCE {
    DX_RSA_EXTERNAL_KEY = 1,
    DX_RSA_INTERNAL_KEY = 2,
    DX_KEY_SOURCE_LASET = 0x7FFFFFFF,
};
/* suit old keymaterial_RSA_PriKey */
struct km_dx_rsa_pri_key {
    uint32_t d_size_bit;
    uint32_t d[DX_RSA_MAX_IMUM_MOD_BUFFER_SIZE_IN_WORDS];
};

/* dx struct keymaterial_RSACRT_PriKey */
struct km_dx_rsa_priv_key_crt {
    uint32_t p_size_bit;
    uint32_t p[DX_RSA_MAX_IMUM_MOD_BUFFER_SIZE_IN_WORDS / KM_NUM_BYTES_2];
    uint32_t q_size_bit;
    uint32_t q[DX_RSA_MAX_IMUM_MOD_BUFFER_SIZE_IN_WORDS / KM_NUM_BYTES_2];
    uint32_t dp_size_bit;
    uint32_t dp[DX_RSA_MAX_IMUM_MOD_BUFFER_SIZE_IN_WORDS / KM_NUM_BYTES_2];
    uint32_t dq_size_bit;
    uint32_t dq[DX_RSA_MAX_IMUM_MOD_BUFFER_SIZE_IN_WORDS / KM_NUM_BYTES_2];
    uint32_t q_inv_size_bit;
    uint32_t q_inv[DX_RSA_MAX_IMUM_MOD_BUFFER_SIZE_IN_WORDS / KM_NUM_BYTES_2];
};

/* old km struct keymaterial_RSA */
struct km_dx_key_rsa {
    uint32_t n_size_bit;
    uint32_t n[DX_RSA_MAX_IMUM_MOD_BUFFER_SIZE_IN_WORDS];
    uint32_t crys_rsa_buff[DX_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS]; /* old struct is error */
    uint32_t e_size_bit;
    uint32_t e[DX_RSA_MAX_IMUM_MOD_BUFFER_SIZE_IN_WORDS];
    enum DX_RSA_DECRYPTO_MODE opera_mode;
    enum DX_RSA_KEY_SOURCE key_source;
    uint32_t crys_pri_int_buff[DX_PKA_PRI_KEY_BUFF_SIZE_IN_WORDS];
    union {
        struct km_dx_rsa_pri_key non_crt;
        struct km_dx_rsa_priv_key_crt crt;
    } pri_key;
};

struct dx_keymaterial_rsa {
    uint32_t magic;
    uint8_t iv[IV_LEN];
    struct km_dx_key_rsa rsa_key;
};

struct soft_keymaterial_rsa {
    uint32_t magic;
    uint8_t iv[IV_LEN];
    uint32_t key_size;
    uint8_t rsa_key[0];
};

struct dx_keymaterial_ec {
    uint32_t magic;
    uint8_t iv[IV_LEN];
    struct dx_ecc_user_pub_key pub_key;
    struct dx_ecc_user_pri_key priv_key;
};

struct dx_keymaterial_symmetric {
    uint32_t magic;
    uint8_t iv[IV_LEN];
    uint32_t key_size;
    uint8_t key[0];
};
#endif