/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: trusted object attr api header
 * Create: 2020-12-23
 */
#ifndef __TEE_OBJ_ATTR_H
#define __TEE_OBJ_ATTR_H

#include "tee_defines.h"

#define OBJ_MIN_SIZE_AES 16
#define OBJ_MAX_SIZE_AES 32
#define OBJ_SIZE_DES 8
#define OBJ_SIZE_DES3 24
#define OBJ_SIZE_SM4 16
#define OBJ_SIZE_SIP_HASH 16
#define OBJ_MAX_SIZE_SM4 64
#define OBJ_MIN_SIZE_HMAC_SM3 10
#define OBJ_MAX_SIZE_HMAC_SM3 128
#define OBJ_MIN_SIZE_HMAC 8
#define OBJ_MAX_SIZE_HMAC 1024
#define OBJ_MIN_SIZE_GENERIC_SECRET 1
#define OBJ_MAX_SIZE_GENERIC_SECRET 512
#define OBJ_MIN_SIZE_RSA_PUB_KEY (512 / 8)
#define OBJ_MIN_SIZE_RSA_KEY_PAIR OBJ_MIN_SIZE_RSA_PUB_KEY
#define OBJ_MAX_SIZE_RSA_PUB_KEY 512
#define OBJ_MAX_SIZE_RSA_KEY_PAIR OBJ_MAX_SIZE_RSA_PUB_KEY
#define OBJ_MAX_SIZE_RSA_CRT_ATTR (OBJ_MAX_SIZE_RSA_KEY_PAIR / 2)
#define OBJ_SIZE_RSA_PUB_EXPONENT 4
#define OBJ_MIN_SIZE_RSA_PUB_EXPONENT 3
#define OBJ_MIN_SIZE_DSA_PUB_KEY (512 / 8)
#define OBJ_MIN_SIZE_DSA_KEY_PAIR OBJ_MIN_SIZE_DSA_PUB_KEY
#define OBJ_MAX_SIZE_DSA_PUB_KEY 128
#define OBJ_MAX_SIZE_DSA_KEY_PAIR OBJ_MAX_SIZE_DSA_PUB_KEY
#define OBJ_MIN_SIZE_DH_KEY_PAIR (256 / 8)
#define OBJ_MAX_SIZE_DH_KEY_PAIR 256
#define OBJ_MIN_SIZE_ECDSA_PUB_KEY 28
#define OBJ_MIN_SIZE_ECDSA_KEY_PAIR OBJ_MIN_SIZE_ECDSA_PUB_KEY
#define OBJ_MAX_SIZE_ECDSA_PUB_KEY 66
#define OBJ_MAX_SIZE_ECDSA_KEY_PAIR OBJ_MAX_SIZE_ECDSA_PUB_KEY
#define OBJ_MIN_SIZE_ECDH_PUB_KEY 28
#define OBJ_MIN_SIZE_ECDH_KEY_PAIR OBJ_MIN_SIZE_ECDH_PUB_KEY
#define OBJ_MAX_SIZE_ECDH_PUB_KEY 66
#define OBJ_MAX_SIZE_ECDH_KEY_PAIR OBJ_MAX_SIZE_ECDH_PUB_KEY
#define OBJ_SIZE_SM2 32
#define OBJ_MAX_SIZE_SM2 66
#define OBJ_SIZE_ED25519_PUB_KEY 32
#define OBJ_SIZE_ED25519_KEY_PAIR OBJ_SIZE_ED25519_PUB_KEY
#define OBJ_MAX_SIZE_ED25519_PUB_KEY 64
#define OBJ_MAX_SIZE_ED25519_KEY_PAIR OBJ_MAX_SIZE_ED25519_PUB_KEY
#define OBJ_SIZE_X25519_PUB_KEY 32
#define OBJ_SIZE_X25519_KEY_PAIR OBJ_SIZE_X25519_PUB_KEY
#define OBJ_MIN_SIZE_PBKDF2 14
#define OBJ_MAX_SIZE_PBKDF2 1024

#ifndef SUPPORT_GP_PANIC
#define TEE_Panic(x) \
    do { \
    } while (0)
#endif

#define MAX_ATTR_COUNT_VALUE 8 /* rsa keypair's attr is 8 */

#define MAX_ATTR_ARRAY_COUNT 5
struct obj_attr_conf_s {
    uint32_t type;
    uint32_t min_attr_count;
    uint32_t max_attr_count;
    uint32_t min_obj_size;
    uint32_t min_attr_array[MAX_ATTR_ARRAY_COUNT];
};

#define ELEM_NUM(array) (sizeof(array) / sizeof((array)[0]))

uint32_t get_attr_count_for_object_type(uint32_t object_type);
uint32_t get_object_size(uint32_t object_type);
const struct obj_attr_conf_s *get_object_attr_conf(const TEE_ObjectHandle object);
TEE_Result check_object_valid(TEE_ObjectHandle object);
#endif
