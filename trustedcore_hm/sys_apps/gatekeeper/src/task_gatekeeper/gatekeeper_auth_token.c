/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: gatekeeper auth token code
 * Create: 2021-11-30
 */
#include "gatekeeper_auth_token.h"
#include <securec.h>
#include <dlist.h>
#include <product_uuid_public.h>
#include <tee_ext_api.h>
#include <tee_log.h>
#include <tee_defines.h>
#include "gatekeeper.h"
#include "gatekeeper_fail_record.h"
#include "gatekeeper_auth_token_whitelist.h"

struct user_auth_token_t {
    struct dlist_node head;
    uint32_t uid;
    struct auth_token_t auth_token;
};

static struct dlist_node g_auth_token_list;
static uint32_t g_auth_token_num = 0;
static bool g_init_flag = false;
static pthread_mutex_t g_list_mutex = PTHREAD_ROBUST_MUTEX_INITIALIZER;

static int32_t mutex_lock_ops(pthread_mutex_t *mutex)
{
    int ret;
    ret = pthread_mutex_lock(mutex);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mutex);

    return ret;
}

static bool add_auth_token(uint32_t uid, const uint8_t *auth_token, uint32_t auth_token_len)
{
    struct user_auth_token_t *node = NULL;

    if (g_auth_token_num >= MAX_RECORD_LIST_NUM) {
        tloge("add record: the number of list node is overstepped\n");
        return false;
    }

    node = TEE_Malloc(sizeof(*node), 0);
    if (node == NULL) {
        tloge("malloc failed\n");
        return false;
    }

    node->uid = uid;
    errno_t rc = memcpy_s(&(node->auth_token), sizeof(node->auth_token),
                          auth_token, auth_token_len);
    if (rc != EOK) {
        tloge("mem copy fail!");
        TEE_Free(node);
        return false;
    }

    dlist_insert_tail(&node->head, &g_auth_token_list);
    g_auth_token_num++;
    return true;
}

bool update_auth_token(uint32_t uid, const uint8_t *auth_token, uint32_t auth_token_len)
{
    struct user_auth_token_t *node = NULL;
    struct user_auth_token_t *temp = NULL;

    if (auth_token == NULL || auth_token_len < sizeof(struct auth_token_t))
        return false;

    if (mutex_lock_ops(&g_list_mutex) != 0) {
        tloge("pthread mutex lock failed\n");
        return false;
    }
    if (!g_init_flag) {
        dlist_init(&g_auth_token_list);
        g_init_flag = true;
    }

    dlist_for_each_entry_safe(node, temp, &g_auth_token_list, struct user_auth_token_t, head) {
        if (node->uid == uid) {
            errno_t rc = memcpy_s(&(node->auth_token), sizeof(node->auth_token),
                auth_token, auth_token_len);
            (void)pthread_mutex_unlock(&g_list_mutex);
            if (rc != EOK) {
                tloge("mem copy fail!");
                return false;
            }
            return true;
        }
    }

    if (!add_auth_token(uid, auth_token, auth_token_len)) {
        tloge("add auth token node failed\n");
        (void)pthread_mutex_unlock(&g_list_mutex);
        return false;
    }
    (void)pthread_mutex_unlock(&g_list_mutex);
    return true;
}

bool delete_auth_token(uint32_t uid)
{
    struct user_auth_token_t *node = NULL;
    struct user_auth_token_t *temp = NULL;

    if (mutex_lock_ops(&g_list_mutex) != 0) {
        tloge("pthread mutex lock for delete token failed\n");
        return false;
    }

    if (!g_init_flag || g_auth_token_num == 0) {
        (void)pthread_mutex_unlock(&g_list_mutex);
        return false;
    }

    dlist_for_each_entry_safe(node, temp, &g_auth_token_list, struct user_auth_token_t, head) {
        if (node->uid == uid) {
            tlogd("find uid %u in list, delete it\n", uid);
            dlist_delete(&node->head);
            TEE_Free(node);
            node = NULL;
            g_auth_token_num--;
        }
    }

    (void)pthread_mutex_unlock(&g_list_mutex);
    return true;
}

static bool query_auth_token(uint32_t uid, uint8_t *auth_token, uint32_t *auth_token_len)
{
    struct user_auth_token_t *node = NULL;
    struct user_auth_token_t *temp = NULL;

    if (mutex_lock_ops(&g_list_mutex) != 0) {
        tloge("pthread mutex lock for query token failed\n");
        return false;
    }

    if (!g_init_flag || g_auth_token_num == 0) {
        (void)pthread_mutex_unlock(&g_list_mutex);
        return false;
    }

    dlist_for_each_entry_safe(node, temp, &g_auth_token_list, struct user_auth_token_t, head) {
        if (node->uid == uid) {
            errno_t rc = memcpy_s(auth_token, *auth_token_len, &(node->auth_token), sizeof(node->auth_token));
            if (rc == EOK) {
                *auth_token_len = sizeof(node->auth_token);
                (void)pthread_mutex_unlock(&g_list_mutex);
                return true;
            }
        }
    }
    (void)pthread_mutex_unlock(&g_list_mutex);
    return false;
}

static bool check_auth_token_permission(const caller_info *caller_info)
{
    TEE_UUID caller_uuid = caller_info->caller_identity.caller_uuid;

    if (caller_info->session_type != SESSION_FROM_TA)
        return false;

    for (uint32_t i = 0; i < (sizeof(g_auth_token_white_lists) / sizeof(g_auth_token_white_lists[0])); i++) {
        if (TEE_MemCompare(&caller_uuid, &(g_auth_token_white_lists[i]), sizeof(g_auth_token_white_lists[i])) == 0)
            return true;
    }

    return false;
}

TEE_Result gk_get_auth_token_timestamp(uint32_t param_types, TEE_Param *params, const caller_info *caller_info)
{
    struct auth_token_t auth_token = {0};
    uint32_t auth_token_len = sizeof(auth_token);
    uint64_t *timestamp = NULL;

    if (params == NULL || caller_info == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!check_auth_token_permission(caller_info)) {
        tloge("no permission for get auth token cmd");
        return TEE_ERROR_ACCESS_DENIED;
    }

    if (!check_param_type(param_types,
                          TEE_PARAM_TYPE_MEMREF_INOUT,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE)) {
        tloge("param check fail for get auth token\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    timestamp = (uint64_t *)params[TEE_PARAM_0].memref.buffer;
    if (params[TEE_PARAM_0].memref.buffer == NULL || params[TEE_PARAM_0].memref.size < sizeof(*timestamp))
        return TEE_ERROR_BAD_PARAMETERS;

    uint32_t uid = *(uint32_t *)params[TEE_PARAM_0].memref.buffer;

    if (!query_auth_token(uid, (uint8_t *)&auth_token, &auth_token_len)) {
        tloge("get auth token failed\n");
        return TEE_ERROR_GENERIC;
    }

    *timestamp = auth_token.timestamp;
    return TEE_SUCCESS;
}
