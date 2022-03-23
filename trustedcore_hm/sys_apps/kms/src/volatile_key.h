/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: definition for kms volatile key
 * Author: chengfuxing@huawei.com
 * Create: 2021-12-7
 */
#ifndef KMS_VOLATILE_KEY_H
#define KMS_VOLATILE_KEY_H
#include "tee_internal_api.h"
#include "kms_pub_def.h"
#define MAX_VOLATILE_KEY_COUNT 5
#define MAX_LENGTH (((MAX_KEY_ID_LEN + 3) / 4) * 4)

struct volatile_key {
    char key_id[MAX_LENGTH];
    struct kms_buffer_data key_blob;
};

bool valid_key_id(const char *key_id);
TEE_Result vkey_list_init(void);
void destroy_vkey_list_lock(void);
TEE_Result insert_volatile_keyblob(const char *key_id, const struct kms_buffer_data *blob);
TEE_Result get_volatile_keyblob(const char *key_id, struct kms_buffer_data *out_blob);
TEE_Result del_volatile_keyblob(const char *key_id);
uint32_t count_volatile_key(void);
#endif
