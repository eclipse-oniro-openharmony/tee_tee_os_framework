/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster keynode header
 * Create: 2020-02-13
 */
#ifndef __KM_KEY_NODE_H
#define __KM_KEY_NODE_H
#include <dlist.h>
#include "km_types.h"
#include "keyblob.h"

typedef struct {
    struct dlist_node key_auth_head;
    uint64_t operation_handle;
    uint32_t last_access_time;
    uint32_t uses_time;
    keymaster_key_param_set_t *auth_params;
    uint32_t auth_params_size;
    keymaster_algorithm_t algorithm;
    keymaster_purpose_t purpose;
    keymaster_padding_t padding;
    keymaster_digest_t digest;
    keymaster_block_mode_t block_mode;
    uint32_t tag_len_bit; // for gcm and hmac
    uint32_t min_tag_len;
    uint8_t *aad_data;
    uint32_t aad_data_size;
    uint8_t *key1; // private key if RSA or EC
    uint32_t key1_size; // private key size in bits for gp or key buffer length for sw engine
    uint8_t *key2; // public key if RSA or EC
    uint32_t key2_size;
    uint8_t *data;
    uint32_t data_size;
    void *crypto_ctxt;
    bool data_started_gcm;
    bool use_soft;
    uint32_t usage_count;
    uint32_t need_clean_ctx;
} key_auth;
#define ADD_USAGE_COUNT 1
#define SUB_USAGE_COUNT 0
TEE_Result add_auth_node(key_auth *key_node);
TEE_Result get_auth_node(uint64_t operation_handle, key_auth **key_node);
TEE_Result free_auth_node(uint64_t op_handle);
TEE_Result change_node_usage_count(uint64_t operation_handle, uint8_t change_flag);
void free_key_node(key_auth *key_node);
void init_auth_list(void);
pthread_mutex_t *get_key_auth_lock(void);
key_auth *generate_keynode(const keyblob_head *keyblob);
#endif
