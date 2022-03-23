/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm number head file
* Author: huawei
* Create: 2020/1/8
*/

#ifndef HSM_COMMAND_H
#define HSM_COMMAND_H

#include <stdint.h>
/* hsm command */
#define HSM_START_MAIN_KEY_INIT_CMD                           0x99000000U
#define HSM_FINISHED_MAIN_KEY_INIT_CMD                        0x99010000U
#define HSM_START_ESTABLISSH_SESSION_CMD                      0x99020000U
#define HSM_FINISHED_ESTABLISSH_SESSION_CMD                   0x99030000U
#define HSM_PRODUCE_SYMMETRIC_KEY_CMD                         0xcc010000U
#define HSM_PRODUCE_ASYMMETRIC_KEY_CMD                        0xcc020000U
#define HSM_DERIVE_HUK_CMD                                    0xcc030100U
#define HSM_DERIVE_EXTERNAL_KEY_CMD                           0xcc030200U
#define HSM_IMPORT_IPK1_CMD                                   0xcc040100U
#define HSM_IMPORT_IPK2_CMD                                   0xcc040200U
#define HSM_PRODUCE_NEGOTIATION_PUBLIC_KEY_CMD                0xcc050000U
#define HSM_PRODUCE_NEGOTIATION_KEY_CMD                       0xcc060000U
#define HSM_SH_KEY_CMD                                        0xcc070000U
#define HSM_UPDATE_GUARDING_KEY_CMD                           0xcc080000U
#define HSM_UPDATE_VERIFY_INFO_CMD                            0xcc090000U
#define HSM_DELETE_CIPHER_CMD                                 0xcc0a0000U
#define HSM_EXPORT_IPK1_CMD                                   0xcc0b0100U
#define HSM_EXPORT_IPK2_CMD                                   0xcc0b0200U
#define HSM_CIPHER_START_ENCRIPT_CMD                          0xbb010100U
#define HSM_CIPHER_START_DECRIPT_CMD                          0xbb010101U
#define HSM_CIPHER_PROCESS_ENCRIPT_CMD                        0xbb010200U
#define HSM_CIPHER_PROCESS_DECRIPT_CMD                        0xbb010201U
#define HSM_CIPHER_FINISH_ENCRIPT_CMD                         0xbb010400U
#define HSM_CIPHER_FINISH_DECRIPT_CMD                         0xbb010401U
#define HSM_MAC_START_CMD                                     0xbb020100U
#define HSM_MAC_PROCESS_CMD                                   0xbb020200U
#define HSM_MAC_FINISH_CMD                                    0xbb020400U
#define HSM_HASH_START_CMD                                    0xbb030100U
#define HSM_HASH_PROCESS_CMD                                  0xbb030200U
#define HSM_HASH_FINISH_CMD                                   0xbb030400U
#define HSM_SIGN_START_CMD                                    0xbb040100U
#define HSM_SIGN_PROCESS_CMD                                  0xbb040200U
#define HSM_SIGN_FINISH_CMD                                   0xbb040400U
#define HSM_VERIFY_START_CMD                                  0xbb050100U
#define HSM_VERIFY_PROCESS_CMD                                0xbb050200U
#define HSM_VERIFY_FINISH_CMD                                 0xbb050400U
#define HSM_GEN_RANDOM_CMD                                    0xbb060000U
#define HSM_BBOX_HISS_CMD                                     0xaa000000U
#define HSM_NOTIFY_PRERESET_HISS_CMD                          0xAA000002U
#define HSM_COUNT_INIT_CMD                                    0x30000000U
#define HSM_COUNT_CREATE_CMD                                  0x30000001U
#define HSM_COUNT_READ_CMD                                    0x30000002U
#define HSM_COUNT_DELETE_CMD                                  0x30000004U
#define HSM_COUNT_INC_CMD                                     0x30000008U
#define HSM_ALGO_CHECK_CMD                                    0xaa000001U
#define HSM_GEN_RPMB_KEY_CMD                                  0xdd000000U
#define HSM_GEN_RPMB_WRAP_KEY_CMD                             0xdd000001U
#define HSM_SOC_VERIFY_SEND_CMD                               0x50000000U
#define HSM_HBOOT1A_TRANS_SEND_CMD                            0x50000001U
#define HSM_RIM_UPDATE_CMD                                    0x60000000U
#define HSM_EFUSE_PWR_ON_CMD                                  0x60000001U
#define HSM_EFUSE_PWR_OFF_CMD                                 0x60000002U

#define TA_ID_LEN_FOUR_WORD                                   4
#define HMAC_LEN_EIGHT_WORD                                   8
#define TA_MAX_NUM                                            16
#define MAIN_KEY_LEN_IN_BYTE                                  80
#define UUID_LEN_IN_BYTE                                      16
#define TA_KEY_LEN_IN_BYTE                                    32
#define LEN_OF_4BYTES                                         4
#define SERVICE_HMAC_LEN                                      32
#define SERVICE_HMAC_WORD_LEN                                 8
#define SERVICE_HMAC_NONE                                     0
#define HMAC_INPUT                                            0
#define HMAC_OUTPUT                                           1
#define SERVICE_HMAC_KEY1                                     1
#define HMAC_TA_KEY_LEN                                       32
#define SERVICE_HMAC_KEY2                                     2
#define HSM_TA_CMD_MASK                                       0xFF000000U
#define HSM_MAIN_KEY_TA_CMD                                   0xAA000000U
#define CONST_NUMBER_3                                        3
#define HMAC_KEY_LEN_32                                       32
#define HSM_CLENT_MSG_LEN                                     3072
#define HSM_SERVICE_MAINKEY_CNT                               1
#define HSM_SERVICE_TAKEY_CNT                                 0

#ifdef STATIC_SKIP
#define STATIC
#else
#define STATIC static
#endif

typedef struct {
    uint32_t cmd;
    uint32_t ta_index;
    uint32_t ta_id[TA_ID_LEN_FOUR_WORD];
    uint32_t job_id;
    uint32_t addr_addr_l;
    uint32_t addr_addr_h;
    uint32_t ddr_data_len;
    uint32_t ddr_para_num;
    uint32_t param_len_0;
    uint32_t param_len_1;
    uint32_t param_len_2;
    uint32_t param_len_3;
    uint32_t param_len_4;
    uint32_t param_len_5;
    uint32_t param_len_6;
    uint32_t param_len_7;
    uint32_t cnt;
    uint32_t hmac[HMAC_LEN_EIGHT_WORD];
} HSM_COMMAND;

typedef struct {
    uint32_t ta_index;
    uint32_t job_id;
    uint32_t mode;
    uint32_t job_state;
    uint32_t process_result;
    uint32_t verify_result;
    uint32_t reserved;
    uint32_t ddr_addr_l;
    uint32_t ddr_addr_h;
    uint32_t ddr_data_len;
    uint32_t ddr_para_num;
    uint32_t param_len_0;
    uint32_t param_len_1;
    uint32_t param_len_2;
    uint32_t param_len_3;
    uint32_t param_len_4;
    uint32_t param_len_5;
    uint32_t param_len_6;
    uint32_t param_len_7;
    uint32_t hmac[HMAC_LEN_EIGHT_WORD];
} HSM_BACK_DATA;

typedef struct {
    uint8_t main_key[MAIN_KEY_LEN_IN_BYTE];
    uint32_t cnt;
} MAIN_KEY_INFO;

typedef struct {
    uint8_t ta_id[UUID_LEN_IN_BYTE]; /* stands for ta id is use for which ta */
    uint8_t ta_key[TA_KEY_LEN_IN_BYTE];  /* ta main key info */
    uint32_t use_flag; /* ta key is using or not */
    uint32_t cnt;
} TA_KEY_INFO;

typedef struct {
    HSM_COMMAND *p_in_msg;
    HSM_BACK_DATA *p_out_msg;
    uint8_t *in_buf;
    uint8_t *out_buf;
} SERVICE_INFO_S;

typedef struct {
    uint8_t *c_key;
    uint32_t key_len;
    uint8_t *ddr_data;
    uint32_t ddr_data_len;
    uint8_t *cmd_data;
    uint32_t cmd_data_len;
    uint8_t *result;
} AS_HMAC_S;

#endif
