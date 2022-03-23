/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Partial calculate implementation of GP functions.
 * Author: aaron.shen
 * Create: 2019/08/20
 */

#ifndef __SECFLASH_SCP03_IMPL_H__
#define __SECFLASH_SCP03_IMPL_H__

#include <stdint.h>
#include "secureflash_derived_key.h"

#define SECFLASH_DEBUG                   0
/*
 * secflash total Error num: 0x8500 0000 ~ 0x8500 ffff
 * 0000 ~ 1fff : used by security flash service
 * 2000 ~ 3fff : product line and API(except sec flash)
 * 4000 ~ 5fff : data link and driver
 * 6000 ~ 7fff : secflash scp03 impl
 * 8000 ~ ffff : reserved
 */
#define SECFLASH_SUCCESS                 0x00000000
#define SECFLASH_FAILURE                 0x85000000
#define SECFLASH_OTHER_API_FAILURE       0x80002000
#define SECFLASH_DATA_LINK_FAILURE       0x85004000

/* SCP03 Error num except GP SW:0x6*** */
enum ERROR_NUM {
    KVN_NOT_SUPPORT = 0x7001,
    RESPONSE_LENGTH_ERR,
    RESPONSE_KEY_INFO_ERR,
    KEY_GET_ERR,
    KEY_NOT_INIT_ERR,
    POINTER_NULL,
    POINTER_LENGTH_ERR,
    INPUT_LEN_ERR,
    VERIFY_ERR,
    MODULE_ID_ERR,
    MEMCPY_ERR,
    MALLOC_ERR,
    ENCRYPT_ERR,
    CHANNEL_STATUS_ERR,
    ERROR_COUNT_ERR,
    BLOCK_COUNT_OVER,
    BLOCK_COUNT_NOT_PAGE,
    RIGHT_ERR,
    RMAC_VERIFY_ERR,
    KCV_VERIFY_ERR,
    BLOCK_VERIFY_ERR,
    KCV_CALCULATE_ERR,
    KDF_CALCULATE_ERR,
    INS_ERR,
    AES_INPUT_KEY_ERR,
    AES_INPUT_DATA_ERR,
    AES_INIT_ERR,
    AES_UPDATE_ERR,
    AES_DOFINAL_ERR,
    AES_SET_KEY_ERR,
    AES_SET_IV_ERR,
    RANDOM_GENERATE_ERR,
    KEY_GENERATE_ERR
};

enum gp_cmd_offset {
    CLA = 0,
    INS,
    P1,
    P2,
    LC,
    CDATA
};

#define GP_SW_LENGTH                      2
#define GP_ADD_EXTENDED_LENGTH            2

/*
 * KDF parameters used in SCP03 calc (if key length is 128bits)
 * [i] || Label || 0x00 || Context || [L]
 *  1      12       1        16        2   bytes
 */
#define SECFLASH_KDF_CONTEXT_LEN         16
#define SECFLASH_LABLE_LEN               12
#define SECFLASH_KDF_MESSAGE_LEN         32
#define SECFLASH_L_64BIT                 0x0040
#define SECFLASH_L_128BIT                0x0080

/* derivation of S-ENC/MAC/RMAC */
#define SECFLASH_SCP03_DERIVATION_SENC   0x04
#define SECFLASH_SCP03_DERIVATION_SMAC   0x06
#define SECFLASH_SCP03_DERIVATION_SRMAC  0x07

#define SECFLASH_XTS_CONSTANT_KEY1       0x84
#define SECFLASH_XTS_CONSTANT_KEY2       0x86

/* host/card Challenge byte length */
#define SECFLASH_CHALLENGE_LENGTH        8
#define SECFLASH_CRYPTOGRAM_LENGTH       16
#define SECFLASH_CMAC_LENGTH             8
#define SECFLASH_CMAC_TOTAL_LENGTH       16

#define SECFLASH_AES_KEY_BIT_LEN         128
#define SECFLASH_AES_KEY_BYTE_LEN        16
#define SECFLASH_AES_KEY_TYPE            0x88
#define KCV_BYTE_LEN                     3
#define BINDING_KEY_DATA_STRUCT_LEN      23
#define SECFLASH_BLOCK_BYTE_LEN          16
#define SECFLASH_IV_BYTE_LEN             16

/*
 * cmac cmd max length (write cmd: 16blocks)
 * '4': CLA-P2; '3': Lc; '2': Block count; "16*16": Data; '16': MAC chaining value
 */
#define SECFLASH_CMAC_CMD_MAX_LEN        281

/*
 * Rmac cmd max length (write cmd: 16blocks)
 * '4110': response Data; '16': MAC chaining value
 */
#define SECFLASH_RMAC_DATA_MAX_LEN        4126

/*
 * encrypt cmd length (binding cmd)
 * '70': Data; '10': Padding value
 */
#define SECFLASH_ENCRYPT_CMD_MAX_LEN     80

#define TEE_CRYPTO_OBJECT_SIZE           32

#define ONE_BYTES_OFFSET                 1
#define TWO_BYTES_OFFSET                 2
#define THREE_BYTES_OFFSET               3
#define FOUR_BYTES_OFFSET                4
#define ONE_BYTE_BITS_OFFSET             8
#define TWO_BYTE_BITS_OFFSET             16
#define THREE_BYTE_BITS_OFFSET           24

/* session key struct */
struct session_sec_channel_key {
    uint8_t senc[SECFLASH_AES_KEY_BYTE_LEN];
    uint8_t smac[SECFLASH_AES_KEY_BYTE_LEN];
    uint8_t srmac[SECFLASH_AES_KEY_BYTE_LEN];
};

/* Key kcv struct */
struct key_kcv {
    uint8_t enc_kcv[KCV_BYTE_LEN];
    uint8_t mac_kcv[KCV_BYTE_LEN];
    uint8_t dek_kcv[KCV_BYTE_LEN];
};

struct scp_challenge {
    uint8_t host_challenge[SECFLASH_CHALLENGE_LENGTH];
    uint8_t card_challenge[SECFLASH_CHALLENGE_LENGTH];
    uint8_t card_cryptogram[SECFLASH_CHALLENGE_LENGTH];
    uint8_t host_cryptogram[SECFLASH_CHALLENGE_LENGTH];
};

struct crypto_info {
    uint8_t *iv;
    uint8_t iv_size;
    uint8_t *key;
    uint32_t key_size;
    uint32_t crypto_algo;
    uint32_t operation_mode;
    uint8_t *data_in;
    uint32_t data_in_size;
    uint8_t *data_out;
    uint32_t max_data_out_size;
};

struct cmd_derivate_info {
    uint32_t module_id;
    uint32_t block_index;
    uint32_t block_count;
    uint32_t phy_block_index;
    uint8_t kvn;
    uint8_t *cmd;
    uint32_t cmd_length;
    uint8_t *data;
    uint8_t *data_out;
    uint32_t max_data_buf;
};

struct data_info {
    uint8_t *data;
    uint32_t data_length;
};

uint32_t secflash_generate_session_keys(struct secflash_keyset *key, uint8_t *host_challenge,
    uint8_t *card_challenge, struct session_sec_channel_key *session_key);
uint32_t secflash_verify_card_cryptogram(struct scp_challenge *data, uint8_t *key);
uint32_t secflash_calculate_host_cryptogram(struct scp_challenge *data, uint8_t *key);
uint32_t secflash_calculate_cmac(uint8_t *apdu_buf, uint32_t data_length, uint8_t extended_length,
    struct data_info mac_chaining_data, uint8_t *key);
uint32_t secflash_verify_rmac(uint8_t *apdu_data_buf, uint32_t length, uint8_t *mac_chaining, uint8_t *key);
uint32_t secflash_encrypt_sensitive_data(struct cmd_derivate_info *info, uint8_t *iv);
uint32_t secflash_decrypt_sensitive_data(struct cmd_derivate_info *info, uint8_t *iv, uint8_t *data_buf,
    uint8_t *out_buf, uint32_t out_buf_length);
#endif
