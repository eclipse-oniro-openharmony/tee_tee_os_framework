/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: implement get key factor
 * Create: 2021-06-07
 */

#include <securec.h>
#include <dlist.h>
#include <pthread.h>
#include <tee_mem_mgmt_api.h>
#include <tee_log.h>
#include <drv_module.h>
#include <drv_call_check.h>
#include <drv_param_type.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <hmdrv_stub.h>

#define MAX_KEY_SIZE    32
struct key_factor_t {
    struct dlist_node head;
    uint64_t secure_id;
    uint8_t key_factor[MAX_KEY_SIZE];
};

#define MAX_RECORD_LIST_NUM 600
static struct dlist_node g_key_factor_list;
static uint32_t g_key_factor_num = 0;
static pthread_mutex_t g_list_mutex = PTHREAD_ROBUST_MUTEX_INITIALIZER;
static bool g_init_flag = false;

static int32_t mutex_lock_ops(pthread_mutex_t *mutex)
{
    int ret;
    ret = pthread_mutex_lock(mutex);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mutex);

    return ret;
}

static bool add_new_key_factor(uint64_t secure_id, uint8_t *key_factor, uint32_t key_len)
{
    struct key_factor_t *node = NULL;

    if (g_key_factor_num >= MAX_RECORD_LIST_NUM) {
        tloge("add record: the number of list node is overstepped\n");
        return false;
    }

    node = TEE_Malloc(sizeof(*node), 0);
    if (node == NULL) {
        tloge("malloc failed\n");
        return false;
    }

    node->secure_id = secure_id;
    errno_t rc = memcpy_s(&(node->key_factor), sizeof(node->key_factor),
                          key_factor, key_len);
    if (rc != EOK) {
        tloge("mem copy fail!");
        TEE_Free(node);
        return false;
    }

    dlist_insert_tail(&node->head, &g_key_factor_list);
    g_key_factor_num++;
    return true;
}

bool add_key_factor(uint64_t secure_id, uint8_t *key_factor, uint32_t key_len)
{
    struct key_factor_t *node = NULL;
    struct key_factor_t *temp = NULL;

    if (key_factor == NULL || key_len == 0)
        return false;

    if (mutex_lock_ops(&g_list_mutex) != 0)
        return false;

    if (!g_init_flag) {
        dlist_init(&g_key_factor_list);
        g_init_flag = true;
    }

    dlist_for_each_entry_safe(node, temp, &g_key_factor_list, struct key_factor_t, head) {
        if (node->secure_id == secure_id) {
            errno_t rc = memcpy_s(&(node->key_factor), sizeof(node->key_factor),
                key_factor, key_len);
            (void)pthread_mutex_unlock(&g_list_mutex);
            if (rc != EOK) {
                tloge("mem copy fail!");
                return false;
            }
            return true;
        }
    }

    /* if not find, add new record */
    if (!add_new_key_factor(secure_id, key_factor, key_len)) {
        tloge("add new record fail!");
        (void)pthread_mutex_unlock(&g_list_mutex);
        return false;
    }

    (void)pthread_mutex_unlock(&g_list_mutex);
    return true;
}

bool delete_key_factor(uint64_t secure_id)
{
    struct key_factor_t *node = NULL;
    struct key_factor_t *temp = NULL;

    if (mutex_lock_ops(&g_list_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return false;
    }

    if (!g_init_flag || g_key_factor_num == 0) {
        (void)pthread_mutex_unlock(&g_list_mutex);
        return false;
    }

    dlist_for_each_entry_safe(node, temp, &g_key_factor_list, struct key_factor_t, head) {
        if (node->secure_id == secure_id) {
            tlogd("find secure_id 0x%llx in list, delete it\n", secure_id);
            dlist_delete(&node->head);
            TEE_Free(node);
            node = NULL;
            g_key_factor_num--;
        }
    }

    (void)pthread_mutex_unlock(&g_list_mutex);
    return true;
}

bool get_key_factor(uint64_t secure_id, uint8_t *key_factor, uint32_t *key_len)
{
    struct key_factor_t *node = NULL;
    struct key_factor_t *temp = NULL;

    if (key_factor == NULL || key_len == NULL || *key_len < MAX_KEY_SIZE)
        return false;

    if (mutex_lock_ops(&g_list_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return false;
    }

    if (!g_init_flag) {
        (void)pthread_mutex_unlock(&g_list_mutex);
        return false;
    }

    dlist_for_each_entry_safe(node, temp, &g_key_factor_list, struct key_factor_t, head) {
        if (node->secure_id == secure_id) {
            tlogd("find secure_id 0x%llx in list\n", secure_id);
            errno_t rc = memcpy_s(key_factor, *key_len, node->key_factor, sizeof(node->key_factor));
            if (rc == EOK) {
                *key_len = sizeof(node->key_factor);
                (void)pthread_mutex_unlock(&g_list_mutex);
                return true;
            }
        }
    }

    (void)pthread_mutex_unlock(&g_list_mutex);
    return false;
}

int32_t gatekeeper_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
    int32_t ret;
    if (params == NULL || params->args == 0) {
        tloge("invalid input param\n");
        return -1;
    }

    uint64_t *args  = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_ADD_KEY_FACTOR, permissions, KEY_FACTOR_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], (uint32_t)args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[1], (uint32_t)args[2]);
        ret = add_key_factor(args[0], (uint8_t *)(uintptr_t)args[1], (uint32_t)args[2]);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_DELETE_KEY_FACTOR, permissions, KEY_FACTOR_GROUP_PERMISSION)
        ret = delete_key_factor(args[0]);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_GET_KEY_FACTOR, permissions, KEY_FACTOR_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[2], sizeof(uint32_t));
        ACCESS_READ_RIGHT_CHECK(args[2], sizeof(uint32_t));
        ACCESS_WRITE_RIGHT_CHECK(args[2], sizeof(uint32_t));
        ACCESS_CHECK_A64(args[1], *(uint32_t *)(uintptr_t)args[2]);
        ACCESS_READ_RIGHT_CHECK(args[1], *(uint32_t *)(uintptr_t)args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[1], *(uint32_t *)(uintptr_t)args[2]);
        ret = get_key_factor(args[0], (uint8_t *)(uintptr_t)args[1], (uint32_t *)(uintptr_t)args[2]);
        args[0] = ret;
        SYSCALL_END
        default:
            return -1;
    }
    return 0;
}
DECLARE_TC_DRV(gatekeeper_drv, 0, 0, 0, TC_DRV_MODULE_INIT, NULL, NULL, gatekeeper_syscall, NULL, NULL);
