/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: the head file of sec api function
* Author: chenyao
* Create: 2019/12/30
*/
#ifndef __SEC_API_H__
#define __SEC_API_H__

#include <stdint.h>

/* Test addr */
#define SEC_BD_SIZE                     0x100
#define SEC_IMG_KEY2_SALT_LEN           32

#define ERR_SEC_KM_REQ_FAILED           0xC6A55A01U
#define ERR_SEC_MEMSET_FAILED           0xC6A55A02U
#define ERR_SEC_TASK_TIMEOUT            0xC6A55A03U
#define ERR_SEC_BDFIFO_TIMEOUT          0xC6A55A04U
#define ERR_SEC_ERR_TIMEOUT             0xC6A55A05U
#define ERR_SEC_TASK_FAILED             0xC6A55A07U
#define ERR_SEC_INIT_FAILED             0xC6A55A0DU
#define ERR_SEC_PARAMETER_ERROR         0x060A000EU

#define SHIFT_LEN_32                    32
#define IMGK2_INPUT_KEY_LEN             32
#define IMGK2_OUTPUT_KEY_LEN            16
#define IMGK2_INPUT_SALT_LEN            32
#define IMGK2_CNT_NUMBER                10000

#define SEC_HASH_BLOCK_MASK             0x3F
#define SEC_AES_BLOCK_MASK              0x0F
#define SEC_SUSPEND_TIMEOUT             3
#define SEC_SUSPEND_DELAT_1MS           1

#define SEC_PROV_KEY_LEN                16

#define SEC_SUCCESS                     0
#define SEC_FAIL                        -1
#define SEC_FIRST_INIT                  0xF
#define SEC_NOT_FIRST_INIT              0x0

#define SEC_SHA1_ZERO_DATA_LEN              0x14
#define SEC_SHA224_ZERO_DATA_LEN            0x1C
#define SEC_SHA256_ZERO_DATA_LEN            0x20
#define SEC_SHA384_ZERO_DATA_LEN            0x30
#define SEC_SHA512_ZERO_DATA_LEN            0x40
#define SEC_SM3_ZERO_DATA_LEN               0x20

/* 1951 pg2 only support HUK_DER/WRAPK1/WRAPK2, pg1 support all */
typedef enum sec_key_load_st {
    KEY_HUK_DER     = 0x1,
    KEY_IMGK1       = 0x3,
    KEY_IMGK2       = 0x5,
    KEY_WRAPK1      = 0x7,
    KEY_WRAPK2      = 0x9
} SEC_KEY_LOAD_S;

typedef enum sec_cipher_mode_st {
    SEC_AES         = 0x2,
    SEC_SM4         = 0x3
} SEC_CIPHER_MODE_S;

typedef enum sec_aes_key_len_st {
    AES_128         = 0x0,
    AES_192         = 0x1,
    AES_256         = 0x2,
} SEC_AES_KEY_LEN_S;

typedef enum {
    HMAC_SHA1       = 0x10,
    HMAC_SHA256     = 0x11,
    HMAC_MD5        = 0x12,
    HMAC_SHA224     = 0x13,
    HMAC_SHA384     = 0x14,
    HMAC_SHA512     = 0x15,
    HMAC_SM3        = 0x26
} SEC_HMAC_TYPE_S;

typedef enum sec_aes_mode_st {
    AES_ECB         = 0x0,
    AES_CBC         = 0x1,
    AES_OFB         = 0x3,
    AES_CTR         = 0x4,
    AES_XTS         = 0x7,
} SEC_AES_MODE_S;

typedef enum {
    OUT_KEY         = 0x0,
    HUK             = 0x1,
    IMGK1           = 0x2,
    IMGK2           = 0x3,
    WRAPK1          = 0x4,
    WRAPK2          = 0x5,
} SEC_KM_KEY_S;

typedef enum {
    SHA1            = 0x0, /* support for GP */
    SHA256          = 0x1,
    MD5             = 0x2,
    SHA224          = 0x3,
    SHA384          = 0x4,
    SHA512          = 0x5,
    SM3             = 0x25
} SEC_HASH_TYPE_S;

typedef enum sec_aes_enc_st {
    AES_ENC         = 0x1,
    AES_DEC         = 0x2
} SEC_AES_ENC_S;

typedef struct {
    unsigned long data_addr;
    unsigned long key_addr;
    unsigned long iv_addr;
    unsigned long result_addr;
    uint32_t data_len;
    unsigned long bd_addr;
    SEC_CIPHER_MODE_S cipher_mode;
    SEC_AES_KEY_LEN_S aes_key_len;
    SEC_AES_MODE_S aes_mode;
    SEC_AES_ENC_S aes_enc;
    SEC_KM_KEY_S key_type;
} SEC_AES_INFO_S;

typedef struct sec_aes_gcm_info_st {
    unsigned long data_addr; // aad + data
    unsigned long key_addr;
    unsigned long iv_addr;
    unsigned long auth_iv_addr;
    unsigned long result_addr;
    unsigned long mac_addr;
    unsigned long cipheroff_addr;
    uint32_t data_len;
    uint32_t aad_len;
    uint32_t tag_len;
    /* long_data_len only used in gcm final */
    uint32_t long_data_len_l;
    uint32_t long_data_len_h;
    unsigned long bd_addr;
    SEC_AES_KEY_LEN_S aes_key_len;
    SEC_AES_ENC_S aes_enc;
    SEC_KM_KEY_S key_type;
} SEC_AES_GCM_INFO_S;

typedef struct {
    unsigned long data_addr;
    unsigned long key_addr;
    unsigned long iv_addr;
    unsigned long result_addr;
    uint32_t data_len;
    /* long_data_len only used in hmac final */
    uint32_t long_data_len_l;
    uint32_t long_data_len_h;
    uint32_t key_len;
    uint32_t mac_len;
    unsigned long bd_addr;
    SEC_KM_KEY_S key_type;
    SEC_HMAC_TYPE_S hmac_type;
} SEC_HMAC_INFO_S;

typedef struct {
    unsigned long data_addr;
    unsigned long result_addr;
    unsigned long iv_addr;
    uint32_t data_len;
    /* long_data_len only used in sha final */
    uint32_t long_data_len_l;
    uint32_t long_data_len_h;
    uint32_t mac_len;
    unsigned long bd_addr;
    SEC_HASH_TYPE_S hash_type;
} SEC_HASH_INFO_S;

typedef struct {
    unsigned long key_addr;
    unsigned long seed_addr;
    unsigned long result_addr;
    uint32_t key_len;
    uint32_t seed_len;
    uint32_t cnt;
    uint32_t mac_len;
    unsigned long bd_addr;
    SEC_KM_KEY_S key_type;
    SEC_HMAC_TYPE_S hmac_type;
} SEC_PBKDF2_INFO_S;

typedef struct {
    unsigned long salt_addr;
    uint32_t salt_size;
    unsigned long der_key_addr;
    uint32_t huk_key_len;
} HUK_DER_INFO_S;

typedef struct {
    uint8_t sec_bd[SEC_BD_SIZE];
} __attribute__((aligned(64)))TEE_SEC_BD;

typedef struct {
    SEC_HASH_TYPE_S                hash_type;
    uint32_t                       data_len;
    const uint8_t                  *out_result;
} hash_zero_map_s;

uint32_t sec_init(uint32_t is_first_flag);
uint32_t sec_km_key_req(SEC_KEY_LOAD_S key_type);

/* AES:ECB CCB XTS CTR OFB     SM4:CBC CTR XTS OFB */
uint32_t sec_aes_sm4(SEC_AES_INFO_S *aes_sm4_info);

/* AES-GCM */
uint32_t sec_aes_gcm_simple(SEC_AES_GCM_INFO_S *aes_gcm_info);
uint32_t sec_aes_gcm_init(SEC_AES_GCM_INFO_S *aes_gcm_info);
uint32_t sec_aes_gcm_update(SEC_AES_GCM_INFO_S *aes_gcm_info);
uint32_t sec_aes_gcm_final(SEC_AES_GCM_INFO_S *aes_gcm_info);
uint32_t sec_aes_gcm_km(SEC_AES_GCM_INFO_S *aes_gcm_info);

/* HMAC HMAC-SM3 */
uint32_t sec_hmac_simple(SEC_HMAC_INFO_S *hmac_info);
uint32_t sec_hmac_init(SEC_HMAC_INFO_S *hmac_info);
uint32_t sec_hmac_update(SEC_HMAC_INFO_S *hmac_info);
uint32_t sec_hmac_final(SEC_HMAC_INFO_S *hmac_info);

/* HASH SM3 */
uint32_t sec_hash_simple(SEC_HASH_INFO_S *hash_info);
uint32_t sec_hash_init(SEC_HASH_INFO_S *hash_info);
uint32_t sec_hash_update(SEC_HASH_INFO_S *hash_info);
uint32_t sec_hash_final(SEC_HASH_INFO_S *hash_info);

/* DERIVE KEY */
uint32_t sec_pbkdf2(SEC_PBKDF2_INFO_S *pbkdf2_info);
uint32_t get_provision_key(uint8_t *provision_key, size_t key_size);

int32_t sec_suspend(void);
int32_t sec_resume(void);

#endif
