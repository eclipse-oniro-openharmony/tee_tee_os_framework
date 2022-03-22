/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: hsm ipc command number
 * Author: huawei
 * Create: 2020/1/7
 */

#ifndef HSM_IPC_COMMAND_H
#define HSM_IPC_COMMAND_H

enum HSM_IPC_MSG_CMD {
    /* crypto cmd */
    HSM_IPC_CIPHER_START_CMD            = 0x3300,
    HSM_IPC_CIPHER_PROCESS_CMD          = 0x3301,
    HSM_IPC_CIPHER_FINISH_CMD           = 0x3302,
    HSM_IPC_MAC_START_CMD               = 0x3303,
    HSM_IPC_MAC_PROCESS_CMD             = 0x3304,
    HSM_IPC_MAC_FINISH_CMD              = 0x3305,
    HSM_IPC_HASH_START_CMD              = 0x3306,
    HSM_IPC_HASH_PROCESS_CMD            = 0x3307,
    HSM_IPC_HASH_FINISH_CMD             = 0x3308,
    HSM_IPC_SIGN_START_CMD              = 0x3309,
    HSM_IPC_SIGN_PROCESS_CMD            = 0x330a,
    HSM_IPC_SIGN_FINISH_CMD             = 0x330b,
    HSM_IPC_VERIFY_START_CMD            = 0x330c,
    HSM_IPC_VERIFY_PROCESS_CMD          = 0x330d,
    HSM_IPC_VERIFY_FINISH_CMD           = 0x330e,
    HSM_IPC_GET_RANDOM_CMD              = 0x330f,

    /* key management cmd */
    HSM_IPC_GENERATE_SYMKEY_CMD         = 0x3310,
    HSM_IPC_GENERATE_ASYMKEY_CMD        = 0x3311,
    HSM_IPC_DERIVE_HUK_CMD              = 0x3312,
    HSM_IPC_DERIVE_KEY_CMD              = 0x3313,
    HSM_IPC_EXCHANGE_CAL_PUB_CMD        = 0x3314,
    HSM_IPC_EXCHANGE_AGREE_KEY_CMD      = 0x3315,
    HSM_IPC_IMPORT_KEY_CMD              = 0x3316,
    HSM_IPC_EXPORT_KEY_CMD              = 0x3317,
    HSM_IPC_UPDATE_PROTECT_KEY_CMD      = 0x3318,
    HSM_IPC_UPDATE_KEY_AUTH_CMD         = 0x3319,
    HSM_IPC_DELETE_KEY_CMD              = 0x331a,
    HSM_IPC_UNWRAP_KEY_CMD              = 0x331b,
    HSM_BBOX_CMD                        = 0x331c,
    HSM_COUNTER_INIT_CMD                = 0x331d,
    HSM_COUNTER_CREATE_CMD              = 0x331e,
    HSM_COUNTER_READ_CMD                = 0x331f,
    HSM_COUNTER_DELETE_CMD              = 0x3320,
    HSM_COUNTER_INC_CMD                 = 0x3321,
    HSM_ALG_CHECK_CMD                   = 0x3322,
    HSM_SOC_VERIFY_CMD                  = 0x3323,
    HSM_IPC_RIM_UPDATE_CMD              = 0x3324,
    HSM_IPC_EFUSE_POWER_ON_CMD          = 0x3325,
    HSM_IPC_EFUSE_POWER_OFF_CMD         = 0x3326,
    HSM_IPC_HBOOT1A_TRANS_CMD           = 0x3327,
    /* notify hsm prereset */
    HSM_NOTIFY_PRERESET_CMD             = 0x5000,

    /* hsm service fuzz test */
    HSM_IPC_SERVICE_FUZZ_CMD            = 0x6000,

    /* rpmb ak key */
    HSM_GEN_RPMBKEY_CMD                 = 0x9000,
    HSM_GEN_RPMB_WARPPINGKEY_CMD        = 0x9001,

    /* this command does not exit, just for index ipc command */
    HSM_MAX_IPC_CMD_INDEX
};
#endif
