/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: definitions for invoke commands
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#ifndef KMS_INVOKE_H
#define KMS_INVOKE_H
#include <string.h>
#include "tee_internal_api.h"

#define CMD_PARAMS_LEN 4
#define MAX_IN_BUFFER_LEN 0x4000000
#define INDEX_0 0
#define INDEX_1 1
#define INDEX_2 2
#define INDEX_3 3
#define SECMGR_UID 1002
#ifdef DEF_ENG
void get_memusage();
#endif
enum kms_cmd_id {
    KMS_CMD_CREATE_KEY = 1,
    KMS_CMD_ENCRYPTO, /* 2 */
    KMS_CMD_ENCRYPTO_BEGIN, /* 3 */
    KMS_CMD_ENCRYPTO_UPDATE, /* 4 */
    KMS_CMD_ENCRYPTO_FINISH, /* 5 */
    KMS_CMD_DECRYPTO, /* 6 */
    KMS_CMD_DECRYPTO_BEGIN, /* 7 */
    KMS_CMD_DECRYPTO_UPDATE, /* 8 */
    KMS_CMD_DECRYPTO_FINISH, /* 9 */
    KMS_CMD_SIGN, /* 10 */
    KMS_CMD_SIGN_BEGIN, /* 11 */
    KMS_CMD_SIGN_UPDATE, /* 12 */
    KMS_CMD_SIGN_FINISH, /* 13 */
    KMS_CMD_VERIFY, /* 14 */
    KMS_CMD_VERIFY_BEGIN, /* 15 */
    KMS_CMD_VERIFY_UPDATE, /* 16 */
    KMS_CMD_VERIFY_FINISH, /* 17 */
    KMS_CMD_IMPORT_KEY, /* 18 */
    KMS_CMD_UPDATE_KEY, /* 19 */
    KMS_CMD_UPDATE_KEY_ID, /* 20 */
    KMS_CMD_DELETE_KEY, /* 21 */
    KMS_CMD_EXPORT_KEY, /* 22 */
    KMS_CMD_MAC_GENERATE, /* 23 */
    KMS_CMD_MAC_GENERATE_BEGIN, /* 24 */
    KMS_CMD_MAC_GENERATE_UPDATE, /* 25 */
    KMS_CMD_MAC_GENERATE_FINISH, /* 26 */
    KMS_CMD_DIGEST, /* 27 */
    KMS_CMD_DIGEST_BEGIN, /* 28 */
    KMS_CMD_DIGEST_UPDATE, /* 29 */
    KMS_CMD_DIGEST_FINISH, /* 30 */
    KMS_CMD_RANDOM, /* 31 */
    KMS_CMD_ABORT, /* 32 */
    KMS_CMD_DERIVE_KEY, /* 33 */
    KMS_CMD_BATCH_KEY_COMMIT, /* 34 */
    KMS_CMD_GET_META, /* 35 */
    KMS_CMD_SEC_EXPORT_KEY, /* 36 */
    KMS_CMD_MAX
};
int32_t kms_cmd_create_key(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_encrypto(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_decrypto(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_digest(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_verify(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_sign(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_mac_generate(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_begin(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_update(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_finish(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_random(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_import_key(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_delete_key(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_abort(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_export_key(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_getmeta(TEE_Param params[CMD_PARAMS_LEN]);
int32_t kms_cmd_kdf(TEE_Param params[CMD_PARAMS_LEN]);
#endif
