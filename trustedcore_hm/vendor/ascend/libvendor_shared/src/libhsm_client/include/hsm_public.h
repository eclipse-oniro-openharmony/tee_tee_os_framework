/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: hsm_public function head
 * Author: chenyao
 * Create: 2020-01-08
 */
#ifndef _HSM_PUBLIC_H_
#define _HSM_PUBLIC_H_

#include "tee_defines.h"
#include "tee_inner_uuid.h"

/* MODE */
#define HSM_DERIVE_KEY_HEAD                     12
#define HSM_KEY_HEAD_SIZE                       12
#define HSM_KEY_INFO_SIZE                       44

#define HSM_MSG_RESUME                          0
#define HSM_CLIENT_DDR_LEN                      3072
#define HSM_CONST_SHIFT_32                      32
#define HSM_IV_SIZE                             16
#define HSM_ALG_SIZE                            4
#define HSM_SALT_SIZE                           4
#define HSM_IRT_NUM_SIZE                        4
#define HSM_SESSION_HANDLE_SIZE                 4
#define HSM_RANDOM_SIZE                         4
#define HSM_SIGN_VER_SALT_LEN                   32
#define HSM_KEY_ELEMENT_SIZE                    32
#define HSM_DOMAIN_SIZE                         512

#define HSM_KEY_PROTECT_SIZE                    152
#define HSM_CHUNK_SIZE                          512
#define HSM_BLOCK_SIZE                          1
#define HSM_IV_TWICE_SIZE                       32
#define HSM_COUNTER_ID_SIZE                     4
#define HSM_COUNTER_VALUE_SIZE                  8
#define HSM_UNIT_COUNTER_SIZE                   44
#define HSM_COUNTER_SIZE                        (44 + 16 * HSM_UNIT_COUNTER_SIZE)
#define HSM_RIM_INFO_SIZE                       544
#define HSM_ROOT_KEY_SIZE                       1024

/* MAX SIZE OF ALL LEN IN CPY */
#define HSM_SYMKEY_MAX_SIZE                     64
#define HSM_ASYMKEY_MAX_SIZE                    1280
#define HSM_IV_MAX_SIZE                         16
#define HSM_AUTH_MAX_SIZE                       32
#define HSM_PROTECTMSG_MAX_SIZE                 184
#define HSM_SIGN_MAX_SIZE                       512
#define HSM_SALT_MAX_SIZE                       64
#define HSM_KEY_APPEND_SIZE                     44
#define HSM_RIM_MAX_SIZE                        1568
#define HSM_BBOX_TIMEOUT                        0x5A5A5A5A

/* HSM ALG CHOOSE */
#define HSM_VER_SUCCESS                         0x5A5A5A5A
#define HSM_VER_FAIL                            0xA5A5A5A5

typedef struct {
    uint32_t            cryptokeyelementid;
    uint8_t             cryptokeyelementtype;
    uint8_t             cryptokeyelementreadaccess;
    uint8_t             cryptokeyelementwriteaccess;
    uint8_t             cryptokeyelementallowpartialaccess;
    uint32_t            cryptokeyelementalgid0;
    uint32_t            cryptokeyelementalgid1;
    uint32_t            cryptokeyelementallowusage;
    uint32_t            cryptokeyelementvaliduntil;
    uint8_t             cryptokeyelementallowprovider;
    uint8_t             cryptokeyelementallowpersist;
    uint16_t            cryptokeyelementformat;
    uint32_t            cryptokeyelementsize;
    uint8_t             *cryptokeyelementvalueref;
} CRYPTO_KEY_ELEMENT;

/* the num hsm service ipc cmd should begin 0x3300 */
enum HSM_IPC_MSG_CMD {
    /* crypto cmd */
    HSM_CIPHER_START_CMD            = 0x3300,
    HSM_CIPHER_PROCESS_CMD          = 0x3301,
    HSM_CIPHER_FINISH_CMD           = 0x3302,
    HSM_MAC_START_CMD               = 0x3303,
    HSM_MAC_PROCESS_CMD             = 0x3304,
    HSM_MAC_FINISH_CMD              = 0x3305,
    HSM_HASH_START_CMD              = 0x3306,
    HSM_HASH_PROCESS_CMD            = 0x3307,
    HSM_HASH_FINISH_CMD             = 0x3308,
    HSM_SIGN_START_CMD              = 0x3309,
    HSM_SIGN_PROCESS_CMD            = 0x330a,
    HSM_SIGN_FINISH_CMD             = 0x330b,
    HSM_VERIFY_START_CMD            = 0x330c,
    HSM_VERIFY_PROCESS_CMD          = 0x330d,
    HSM_VERIFY_FINISH_CMD           = 0x330e,
    HSM_GET_RANDOM_CMD              = 0x330f,

    /* key management cmd */
    HSM_GENERATE_SYMKEY_CMD         = 0x3310,
    HSM_GENERATE_ASYMKEY_CMD        = 0x3311,
    HSM_DERIVE_HUK_CMD              = 0x3312,
    HSM_DERIVE_KEY_CMD              = 0x3313,
    HSM_EXCHANGE_CAL_PUB_CMD        = 0x3314,
    HSM_EXCHANGE_AGREE_KEY_CMD      = 0x3315,
    HSM_IMPORT_KEY_CMD              = 0x3316,
    HSM_EXPORT_KEY_CMD              = 0x3317,
    HSM_UPDATE_PROTECT_KEY_CMD      = 0x3318,
    HSM_UPDATE_KEY_AUTH_CMD         = 0x3319,
    HSM_DELETE_KEY_CMD              = 0x331a,
    HSM_UNWRAP_KEY_CMD              = 0x331b,
    HSM_BBOX_CMD                    = 0x331c,
    HSM_COUNTER_INIT_CMD            = 0x331d,
    HSM_COUNTER_CREATE_CMD          = 0x331e,
    HSM_COUNTER_READ_CMD            = 0x331f,
    HSM_COUNTER_DELETE_CMD          = 0x3320,
    HSM_COUNTER_INC_CMD             = 0x3321,
    HSM_ALG_CHECK_CMD               = 0x3322,
    HSM_SOC_VERIFY_CMD              = 0x3323,
    HSM_RIM_VALUE_UPDATE_CMD        = 0x3324,
    HSM_EFUSE_POWER_ON_CMD          = 0x3325,
    HSM_EFUSE_POWER_OFF_CMD         = 0x3326,
    HSM_HBOOT1A_TRANS_CMD           = 0x3327,

    /* notify prereset cmd */
    HSM_NOTIFY_PRERESET_CMD         = 0x5000,

    /* notify prereset cmd */
    HSM_SERVICE_FUZZ_CMD            = 0x6000,

    /* rpmb ak key */
    HSM_GEN_RPMBKEY_CMD             = 0x9000,
    HSM_GEN_RPMB_WARPPINGKEY_CMD    = 0x9001,
};

static const TEE_UUID g_hsm_uuid = TEE_SERVICE_HSM;

#endif
