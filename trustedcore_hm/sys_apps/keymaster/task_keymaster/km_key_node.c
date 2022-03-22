/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: process keymaster key node
 * Create: 2012-07-16
 */

#include "tee_log.h"
#include "keymaster_defs.h"
#include "securec.h"
#include "km_keynode.h"
#include "keyblob.h"
#include "crypto_wrapper.h"
#include "keyblob.h"
#include "tee_crypto_api.h"
#include "pthread.h"

static struct dlist_node g_key_auth_list;
static pthread_mutex_t g_key_auth_lock;

pthread_mutex_t *get_key_auth_lock(void)
{
    return &g_key_auth_lock;
}

void init_auth_list(void)
{
    dlist_init(&g_key_auth_list);
}
static TEE_Result lock_auth_list(void)
{
    int ret;

    ret = pthread_mutex_lock(get_key_auth_lock());
    return (ret == 0) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}
static void unlock_auth_list(void)
{
    int ret;

    ret = pthread_mutex_unlock(get_key_auth_lock());
    if (ret != 0)
        tloge("mutex_unlock failed 0x%x", ret);

    return;
}

TEE_Result add_auth_node(key_auth *key_node)
{
    TEE_Result ret;
    if (key_node == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = lock_auth_list();
    if (ret != TEE_SUCCESS)
        return ret;

    key_node->usage_count = 0;
    dlist_insert_tail(&key_node->key_auth_head, &g_key_auth_list);

    unlock_auth_list();

    return ret;
}

TEE_Result change_node_usage_count(uint64_t operation_handle, uint8_t change_flag)
{
    key_auth *node = NULL;
    TEE_Result ret = lock_auth_list();
    if (ret != TEE_SUCCESS)
        return ret;
    dlist_for_each_entry(node, &g_key_auth_list, key_auth, key_auth_head) {
        if (node->operation_handle == operation_handle) {
            tlogd("find key_node\n");
            if (change_flag == ADD_USAGE_COUNT && node->usage_count == 0) {
                node->usage_count++;
            } else if (change_flag == SUB_USAGE_COUNT && node->usage_count == 1) {
                node->usage_count--;
            } else {
                tloge("operation handle usage count error\n");
                ret = TEE_ERROR_GENERIC;
            }
            break;
        }
    }
    unlock_auth_list();
    return ret;
}

TEE_Result get_auth_node(uint64_t operation_handle, key_auth **key_node)
{
    TEE_Result ret;
    key_auth *node = NULL;
    if (key_node == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    *key_node = NULL;
    ret = lock_auth_list();
    if (ret != TEE_SUCCESS)
        return ret;
    dlist_for_each_entry(node, &g_key_auth_list, key_auth, key_auth_head) {
        if (node->operation_handle == operation_handle) {
            tlogd("find key_node\n");
            *key_node = node;
            break;
        }
    }
    unlock_auth_list();
    return (*key_node != NULL) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result free_auth_node(uint64_t op_handle)
{
    TEE_Result ret;
    key_auth *node = NULL;
    key_auth *tmp  = NULL;
    bool con       = false;
    ret            = lock_auth_list();
    if (ret != TEE_SUCCESS)
        return ret;
    dlist_for_each_entry_safe(node, tmp, &g_key_auth_list, key_auth, key_auth_head) {
        if (node->operation_handle == op_handle) {
            dlist_delete(&node->key_auth_head);
            free_key_node(node);
            TEE_Free(node);
            node = NULL;
            con  = true;
            break;
        }
    }
    unlock_auth_list();
    if (!con) {
        tloge("not find key node\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static void init_key_node(key_auth *key_node, const keyblob_head *keyblob)
{
    key_node->last_access_time = 0;
    key_node->uses_time        = 0;
    key_node->auth_params_size = keyblob->hidden_offset - keyblob->hw_enforced_offset;
}

static void clean_key_node(key_auth **key_node_ptr)
{
    TEE_Free((*key_node_ptr)->auth_params);
    (*key_node_ptr)->auth_params = NULL;
    TEE_Free(*key_node_ptr);
    *key_node_ptr = NULL;
}

key_auth *generate_keynode(const keyblob_head *keyblob)
{
    if (keyblob == NULL)
        return NULL;

    uint8_t *p         = (uint8_t *)keyblob;
    key_auth *key_node = (key_auth *)TEE_Malloc(sizeof(key_auth), 0);
    if (key_node == NULL)
        return NULL;

    TEE_GenerateRandom((uint8_t *)&key_node->operation_handle, sizeof(uint64_t));
    if (key_node->operation_handle == 0) {
        tloge("key_node->operation_handle random failed\n");
        TEE_Free(key_node);
        return NULL;
    }
    init_key_node(key_node, keyblob);
    if (key_node->auth_params_size == 0) {
        tloge("key_node auth_params_size is 0\n");
        TEE_Free(key_node);
        return NULL;
    }
    key_node->auth_params = (keymaster_key_param_set_t *)TEE_Malloc(key_node->auth_params_size, 0);
    if (key_node->auth_params == NULL) {
        tloge("key_node malloc failed\n");
        TEE_Free(key_node);
        key_node = NULL;
        return NULL;
    }
    errno_t rc = memcpy_s((void *)key_node->auth_params, key_node->auth_params_size, p + keyblob->hw_enforced_offset,
                          key_node->auth_params_size);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        clean_key_node(&key_node);
        return NULL;
    }
    return key_node;
}

void free_key_node(key_auth *key_node)
{
    if (key_node == NULL)
        return;
    if (key_node->auth_params != NULL) {
        TEE_Free(key_node->auth_params);
        key_node->auth_params = NULL;
    }
    if (key_node->aad_data != NULL) {
        TEE_Free(key_node->aad_data);
        key_node->aad_data = NULL;
    }
    if (key_node->key1 != NULL) {
        if (memset_s(key_node->key1, key_node->key1_size, 0, key_node->key1_size))
            tloge("key_node->key1 memset_s failed\n");
        TEE_Free(key_node->key1);
        key_node->key1      = NULL;
        key_node->key1_size = 0;
    }
    /* in soft, key2 == key1 */
    if (key_node->key2 != NULL && !key_node->use_soft) {
        TEE_Free(key_node->key2);
        key_node->key2      = NULL;
        key_node->key2_size = 0;
    } else {
        key_node->key2 = NULL;
    }
    if (key_node->data != NULL) {
        TEE_Free(key_node->data);
        key_node->data = NULL;
    }
    if (key_node->crypto_ctxt != NULL) {
        TEE_FreeOperation(key_node->crypto_ctxt);
        key_node->crypto_ctxt = NULL;
    }
}

