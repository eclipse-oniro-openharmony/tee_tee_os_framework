/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Safety operator
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#include "kms_key_node.h"
#include "tee_log.h"
#include "pthread.h"
#include "securec.h"
#include "gp_api_adaptation.h"

static struct kms_key_node g_key_node_list;
static pthread_mutex_t g_key_node_lock;
static bool g_key_node_list_init_flag = false;

void destroy_node_list_lock(void)
{
    if (g_key_node_list_init_flag) {
        if (pthread_mutex_destroy(&g_key_node_lock) != 0) {
            tloge("destroy key node list lock failed");
            return;
        }
        g_key_node_list_init_flag = false;
    }
}

TEE_Result key_node_init(void)
{
    int32_t ret = pthread_mutex_init(&g_key_node_lock, NULL);
    if (ret != 0) {
        tloge("key node init: key node lock init fail");
        return TEE_ERROR_GENERIC;
    }
    g_key_node_list.p_next = NULL;
    g_key_node_list_init_flag = true;
    return TEE_SUCCESS;
}

TEE_Result add_key_node(struct kms_key_node *key_node)
{
    if (key_node == NULL) {
        tloge("add key node: null ptr");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (pthread_mutex_lock(&g_key_node_lock) != 0) {
        tloge("add key node: key node lock fail");
        return TEE_ERROR_GENERIC;
    }
    key_node->p_next = g_key_node_list.p_next;
    key_node->using_flag = IDLE;
    g_key_node_list.p_next = key_node;
    if (pthread_mutex_unlock(&g_key_node_lock) != 0) {
        tloge("add key node: key node unlock fail");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

TEE_Result set_ophandle_state(uint64_t operation_handle, enum key_node_status state)
{
    if (state != USING && state != IDLE) {
        tloge("invalid state param, state %u", state);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (pthread_mutex_lock(&g_key_node_lock) != 0) {
        tloge("update key node: key node lock fail");
        return TEE_ERROR_BUSY;
    }

    struct kms_key_node *node = g_key_node_list.p_next;
    TEE_Result ret = TEE_ERROR_ITEM_NOT_FOUND;
    while (node != NULL) {
        if (node->opt_handle == operation_handle) {
            tlogd("find key node\n");
            if (node->using_flag != USING || state != USING) {
                node->using_flag = state;
                ret = TEE_SUCCESS;
            } else {
                tloge("operation handle is using now, can't re-entry\n");
                ret = TEE_ERROR_ACCESS_CONFLICT;
            }
            break;
        }
        node = node->p_next;
    }
    if (pthread_mutex_unlock(&g_key_node_lock) != 0) {
        tloge("update key node: key node unlock fail");
        return TEE_ERROR_BAD_STATE;
    }
    return ret;
}

TEE_Result get_key_node(uint64_t operation_handle, struct kms_key_node **key_node)
{
    if (key_node == NULL) {
        tloge("get key node: input is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (pthread_mutex_lock(&g_key_node_lock) != 0) {
        tloge("get key node: key node lock fail");
        return TEE_ERROR_GENERIC;
    }
    struct kms_key_node *node = g_key_node_list.p_next;
    *key_node = NULL;

    while (node != NULL) {
        if (node->opt_handle == operation_handle) {
            *key_node = node;
            break;
        }
        node = node->p_next;
    }

    if (pthread_mutex_unlock(&g_key_node_lock) != 0) {
        tloge("get key node: key node unlock fail");
        return TEE_ERROR_GENERIC;
    }
    return (*key_node != NULL) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

struct kms_key_node *alloc_init_key_node(enum key_engine_type eng_type)
{
    struct kms_key_node *key_node = TEE_Malloc(sizeof(struct kms_key_node), 0);
    int32_t max_random_number = MAX_GENERATE_RANDOM_TIME;
    if (key_node == NULL) {
        tloge("alloc init key node: alloc fail");
        return NULL;
    }
    /* generate not repeat operate handle */
    if (pthread_mutex_lock(&g_key_node_lock) != 0) {
        tloge("alloc init key node: key node lock fail");
        TEE_Free(key_node);
        return NULL;
    }
    key_node->eng_type = eng_type;
    key_node->using_flag = IDLE;
    bool repeat = false;
    do {
        TEE_GenerateRandom((uint8_t *)&(key_node->opt_handle), sizeof(key_node->opt_handle));
        /* random check is repeat */
        struct kms_key_node *node = g_key_node_list.p_next;
        max_random_number--;
        repeat = false;
        while (node != NULL) {
            if (node->opt_handle == key_node->opt_handle) {
                repeat = true;
                break;
            }
            node = node->p_next;
        }
    } while (repeat && max_random_number != 0);
    if (pthread_mutex_unlock(&g_key_node_lock) != 0) {
        tloge("alloc init key node: key node unlock fail");
        TEE_Free(key_node);
        return NULL;
    }
    if (repeat) {
        tloge("alloc init key node: random has some problem 0x%llx", key_node->opt_handle);
        TEE_Free(key_node);
        key_node = NULL;
    }
    return key_node;
}
/* void *key_opera_input need free by engine before call this func */
static void free_key_node(struct kms_key_node *node)
{
    if (node == NULL)
        return;
    gp_key_opera_free((struct gp_key_opera_input *)node->key_operate);
    node->key_operate = NULL;
    errno_t rc = memset_s(node, sizeof(*node), 0, sizeof(*node));
    if (rc != EOK)
        tloge("free key node: memory clean fail");
    TEE_Free(node);
}

TEE_Result delete_free_key_node(uint64_t op_handle)
{
    if (pthread_mutex_lock(&g_key_node_lock) != 0) {
        tloge("free key node: key node lock fail");
        return TEE_ERROR_GENERIC;
    }
    struct kms_key_node *node = g_key_node_list.p_next;
    struct kms_key_node *tmp = &g_key_node_list;
    bool find = false;
    while (node != NULL) {
        if (node->opt_handle == op_handle) {
            tmp->p_next = node->p_next;
            free_key_node(node);
            node = NULL;
            find = true;
            break;
        }
        tmp = node;
        node = node->p_next;
    }

    if (pthread_mutex_unlock(&g_key_node_lock) != 0) {
        tloge("key node init: key node unlock fail");
        return TEE_ERROR_GENERIC;
    }

    if (!find) {
        tloge("delete key node: not find key node 0x%llx", op_handle);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}
