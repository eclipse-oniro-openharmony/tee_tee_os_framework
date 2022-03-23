/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2019. All rights reserved.
 * Description: hw auth token
 * Create: 2015-01-17
 */
#ifndef __HW_AUTH_TOKEN_H
#define __HW_AUTH_TOKEN_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#undef UINT32_MAX
#define UINT32_MAX 4294967295U
#define HMAC_SIZE  32

typedef enum {
    HW_AUTH_NONE        = 0,
    HW_AUTH_PASSWORD    = 1 << 0,
    HW_AUTH_FINGERPRINT = 1 << 1,
    /* Additional entries should be powers of 2 */
    HW_AUTH_ANY = UINT32_MAX,
} hw_authenticator_type_t;

/*
 * Data format for an authentication record
 * used to prove successful authentication
 */
typedef struct __attribute__((__packed__)) {
    uint8_t version; /* Current version is 0 */
    uint64_t challenge;
    uint64_t user_id;            /* secure user ID, not Android user ID */
    uint64_t authenticator_id;   /* secure authenticator ID */
    uint32_t authenticator_type; /* hw_authenticator_type_t, in network order */
    uint64_t timestamp;          /* in network order */
    uint8_t hmac[HMAC_SIZE];
} hw_auth_token_t;

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */
#endif /* ANDROID_HARDWARE_HW_AUTH_TOKEN_H */
