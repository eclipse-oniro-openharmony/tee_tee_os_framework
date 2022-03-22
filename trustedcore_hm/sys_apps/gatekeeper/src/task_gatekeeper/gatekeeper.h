/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2020. All rights reserved.
 * Description: gatekeeper ta main code head file
 * Create: 2015-08-08
 * History: 2019-01-18 jiashi restruct
 */
#ifndef _GATEKEEPER_H_
#define _GATEKEEPER_H_

#include <stdint.h>
#include <stdbool.h>

/*
 * @ingroup  TEE_COMMON_DATA
 *
 * The Supported CMD IDs of the secure service gatekeeper
 */
enum SVC_GATEKEEPER_CMD_ID {
    GK_CMD_ID_INVALID = 0x0,
    GK_CMD_ID_ENROLL,
    GK_CMD_ID_VERIFY,
    GK_CMD_ID_DEL_USER,
    GK_CMD_ID_GET_RETRY_TIMES,
    GK_CMD_ID_SET_LOCK_STATUS,
    GK_CMD_ID_GET_LOCK_STATUS,
    GK_CMD_ID_GET_AUTH_TOKEN,
};

#define BIT_32                          32
#define SWAP_32(x)  \
                    (((uint32_t)(x) << 24) | (((uint32_t)(x) & 0xff00) << 8) | \
                    (((uint32_t)(x) & 0x00ff0000) >> 8) | ((uint32_t)(x) >> 24))
#define BE32(val) SWAP_32(val)
#define ntoh(n) BE32(n)
#define hton(h) BE32(h)

#define GATEKEEPER_HIDL_SERVICE_PKGN    "/vendor/bin/hw/android.hardware.gatekeeper@1.0-service"
#define GATEKEEPER_HIDL_SERVICE_UID     1000
#define SYSTEM_SERVER "system_server"
#define SYSTEM_SERVER_SERVICE_UID     1000

#define GATEKEEPER_MAGIC_NUM            0x4A4B4C4D
#define HANDLE_FLAG_THROTTLE_SECURE     1
#define HANDLE_VERSION_THROTTLE         2
#define IV_LEN                          16
#define PASSWORD_MAX_SZIE               256
#define HMAC_SIZE                       32
#define HMAC_SIZE_INBITS                (HMAC_SIZE * 8)
#define PRIMARY_USER_ID            0
#define PRIMARY_FAKE_USER_ID            100000

#define FAIL_RECORD_RPMB_FILENAME       "sec_storage_data/fail_reocrd_rpmb"
#define PRIMARY_RECORD_RPMB_FILENAME    "primary_fail_reocrd_rpmb"

#define INSE_TEE_POWER_ID               1
#define ROT_SIZE                        32

#define TIMEOUT_MS                      20000
#define MILLISECOND                     1000ULL
#define FAIL_COUNTS                     65
#define DEAD_BASE                       0xDEAD0000
#define TEE_PARAM_0                     0
#define TEE_PARAM_1                     1
#define TEE_PARAM_2                     2
#define TEE_PARAM_3                     3
#define TEE_PARAM_COUNT                 4
#ifndef GK_SIZE_4K
#define GK_SIZE_4K                      4096
#endif

/*
 * There are two reasons for setting the threshold value of 100:
 * 1. The gatekeeper TA and the waver TA should be consistent.
 * Considering the power consumption of the weaver chip, the chip
 * does not start the timer in the case of fewer failures.
 * 2. When the failure count reaches 100 times, the freeze time
 * of the framework and gatekeeper both reach about 1 hour, then
 * the freeze time can smoothly transition.
 */
#define START_FAILURE_COUNTER 100
#define MAX_FAILURE_COUNTER   140
#define BASE_FAIL_COUNTER     30U

#define WAIT_TIME_UNIT 30U
#define WAIT_TIME_DAY  (24 * 60 * 60)

#define MAX_SIGN_SIZE (sizeof(uint8_t) + 2 * sizeof(uint64_t) + PASSWORD_MAX_SZIE)
#define MAX_KEY_SIZE 32

struct password_handle_t {
        uint8_t version;
        uint64_t user_id; // secure id
        uint64_t flags;
        uint64_t salt;
        uint8_t signature[HMAC_SIZE]; // version, user_id, flags include in signature
        bool hardware_backed;
} __attribute__((__packed__));

struct gatekeeper_handle {
        struct password_handle_t password_handle;
};

struct session_identity {
    uint32_t len;
    char val[1];
};

struct gk_buffer {
    uint64_t buff;
    uint32_t size;
};

enum handle_versoin_id {
    /* Version 2 is unused in 2016.6.30, now only old 6x (Berlin) product is use version 2. */
    HANDLE_VERSION_3 = 3,
    /*
     * Version 5 is used in 2019.10.08, compared with the previous version,
     * the failure count record rpmb is added, and the anti-blasting adopts google mechanism
     */
    HANDLE_VERSION_5 = 5,
    /*
     * Version 6 is used in 2021.01.12, The password hash is added to HMAC key derivation.
     * In addition, increase the number of key calculation to extend the blasting time.
     */
    HANDLE_VERSION_6 = 6,
    /*
     * Version 7 is used in 2021.06.08, enhance
     */
    HANDLE_VERSION_7 = 7,
};

#endif
