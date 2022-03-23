/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for MSP power module.
 * Author : w00371137
 * Create: 2019/12/25
 */

#ifndef __MSPC_POWER_H__
#define __MSPC_POWER_H__

#include <stdint.h>

#define TEE_MSPC_SET_ACCESS         0xff00
#define TEE_MSPC_CLR_ACCESS         0xff04
#define TEE_MSPC_TRIGGER_UPGRADE    0xff08
#define TEE_MSPC_CHECK_SECFLASH     0xff0c
#define TEE_MSPC_RECOVERY           0xff10
#define TEE_MSPC_CHECK_READY        0xfff0
#define TEE_MSPC_POWER_ON           0xfff4
#define TEE_MSPC_POWER_OFF          0xfff8

enum mspc_vote_id {
    MSPC_SECFLASH_VOTE_ID        = 0,
    MSPC_BIO_VOTE_ID             = 1,
    MSPC_ROT_VOTE_ID             = 2,
    MSPC_ART_VOTE_ID             = 3,
    MSPC_STRONGBOX_VOTE_ID       = 4,
    MSPC_WEAVER_VOTE_ID          = 5,
    MSPC_FILE_CRYPTO_VOTE_ID     = 6,
    MSPC_FACTORY_VOTE_ID         = 7,
    MSPC_VOICEID_VOTE_ID         = 8,
    MSPC_FINGERPRINT_VOTE_ID     = 9,
    MSPC_FINGERPRINT_UD_VOTE_ID  = 10,
    MSPC_WEAVER_SECTIMER_VOTE_ID = 11,
    MSPC_MAX_VOTE_ID             = 12,
};

enum mspc_state {
    MSPC_STATE_POWER_DOWN         = 0,
    MSPC_STATE_POWER_UP           = 1,
    MSPC_STATE_NATIVE_READY       = 3,
    MSPC_STATE_POWER_DOWN_DOING   = 4,
    MSPC_STATE_POWER_UP_DOING     = 5,
#ifdef CONFIG_MSPC_DCS_SUPPORT
    MSPC_STATE_DCS_UPGRADE_DONE   = 7,
#endif
    MSPC_STATE_SECFLASH           = 8,
    MSPC_STATE_MAX,
};

union mspc_vote_status {
    uint64_t value;
    struct {
        uint32_t secflash : 4;
        uint32_t bio_servce : 4;
        uint32_t rot : 4;
        uint32_t art : 4;
        uint32_t strongbox : 4;
        uint32_t weaver : 4;
        uint32_t file_crypto : 4;
        uint32_t factory : 4;
        uint32_t voiceid : 4;
        uint32_t fingerprint : 4;
        uint32_t fingerprint_ud : 4;
        uint32_t weaver_sectimer : 4;
        uint64_t reserved : 16;
    } status;
};

enum mspc_vote_cmd {
    MSPC_VOTE_ON   = 0x38765F4B,
    MSPC_VOTE_OFF  = 0xC789A0B4,
};

uint32_t mspc_get_power_status(void);
uint32_t mspc_get_shared_ddr(void);
int32_t mspc_power_on(uint32_t vote_id);
int32_t mspc_power_off(uint32_t vote_id);
int32_t mspc_wait_state(uint32_t state, uint32_t timeout);
int32_t mspc_wait_native_ready(uint32_t timeout);
void mspc_set_access_flag(void);
void mspc_clear_access_flag(void);
int32_t mspc_power_init(void);
int32_t mspc_power_suspend(void);
uint32_t mspc_power_fac_mode_entry(uint32_t reserved);
uint32_t mspc_power_fac_mode_exit(uint32_t reserved);
void mspc_power_status_dump(void);
#endif /* __MSPC_POWER_H__ */
