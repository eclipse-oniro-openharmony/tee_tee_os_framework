/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: public struct or define
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#ifndef KMS_KMS_KEY_NODE_H
#define KMS_KMS_KEY_NODE_H

#include "kms_pub_def.h"
#include "pthread.h"

#define KEY_NODE_RESERVE_NUMBER 10
#define MAX_GENERATE_RANDOM_TIME 3

enum key_node_status {
    IDLE = 0,
    USING = 1,
};

struct kms_key_node {
    struct kms_key_node *p_next;
    uint64_t opt_handle;
    enum key_node_status using_flag;
    enum key_engine_type eng_type;
    void *key_operate;
    uint32_t reserve[KEY_NODE_RESERVE_NUMBER];
};
TEE_Result key_node_init(void);
struct kms_key_node *alloc_init_key_node(enum key_engine_type eng_type);
TEE_Result delete_free_key_node(uint64_t op_handle);
TEE_Result get_key_node(uint64_t operation_handle, struct kms_key_node **key_node);
TEE_Result add_key_node(struct kms_key_node *key_node);
void destroy_node_list_lock(void);
pthread_mutex_t *get_node_lisk_lock(void);
TEE_Result set_ophandle_state(uint64_t operation_handle, enum key_node_status state);
#endif
