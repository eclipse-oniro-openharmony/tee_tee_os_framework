/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2020. All rights reserved.
 * Description: gatekeeper proc failed record code
 * Create: 2015-08-08
 * History: 2019-01-18 jiashi restruct
 */
#include "gatekeeper_fail_record.h"
#include <securec.h>
#include <tee_defines.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include "gatekeeper.h"

static struct dlist_node g_fail_record_list;
static uint32_t g_fail_record_num = 0;
static bool g_init_flag = false;
static pthread_mutex_t g_list_mutex = PTHREAD_ROBUST_MUTEX_INITIALIZER;

int gk_mutex_lock_ops(pthread_mutex_t *mutex)
{
    int ret;
    ret = pthread_mutex_lock(mutex);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mutex);

    return ret;
}

void init_fail_list(void)
{
    if (!g_init_flag) {
        dlist_init(&g_fail_record_list);
        g_init_flag = true;
    }
}

static bool check_param_and_init_flag(const struct failure_record_uid_t *record_uid)
{
    if (record_uid == NULL) {
        tloge("input is null\n");
        return false;
    }

    if (!g_init_flag) {
        tloge("list is not initialized\n");
        return false;
    }

    return true;
}

static void print_record(const char *log_tag, const struct failure_record_uid_t *record_uid)
{
#ifndef LOG_ON
    (void)log_tag;
    (void)record_uid;
#endif

    tlogd("%s: find uid:%u version:%c secure_user_id 0x%llx\n", log_tag,
          record_uid->uid, record_uid->version, record_uid->record.secure_user_id);
    tlogd("%s: timestamp 0x%llx ms, failure_counter %u\n", log_tag,
          record_uid->record.last_checked_timestamp,
          record_uid->record.failure_counter);
}

static struct fail_record_t *get_list_node_v3(uint64_t secure_user_id, uint8_t version)
{
    struct fail_record_t *node = NULL;
    struct fail_record_t *temp = NULL;
    struct failure_record_uid_t *node_record = NULL;

    dlist_for_each_entry_safe(node, temp, &g_fail_record_list, struct fail_record_t, fail_record_head) {
        node_record = &(node->record_uid);
        if ((node_record->version == version) &&
            (node_record->record.secure_user_id == secure_user_id))
            return node;
    }

    return NULL;
}

static struct fail_record_t *get_list_node_v5(uint32_t uid, uint8_t version)
{
    struct fail_record_t *node = NULL;
    struct fail_record_t *temp = NULL;
    struct failure_record_uid_t *node_record = NULL;

    dlist_for_each_entry_safe(node, temp, &g_fail_record_list, struct fail_record_t, fail_record_head) {
        node_record = &(node->record_uid);
        if (node_record->uid == uid && node_record->version >=HANDLE_VERSION_5 &&
            node_record->version <= version)
            return node;
    }

    return NULL;
}

static bool g_duplicate_flag = false;
bool duplicate_record_exist()
{
    return g_duplicate_flag;
}

static bool find_and_update(struct failure_record_uid_t *record_uid, bool init_flag)
{
    struct fail_record_t *node = NULL;

    node = get_list_node_v5(record_uid->uid, record_uid->version);
    if (node != NULL) {
        g_duplicate_flag = true;
        if (init_flag &&
            record_uid->record.last_checked_timestamp < node->record_uid.record.last_checked_timestamp)
            return true;

        errno_t rc = memcpy_s(&(node->record_uid), sizeof(node->record_uid),
                              record_uid, sizeof(*record_uid));
        if (rc != EOK)
            tlogw("mem copy fail");

        print_record("add fail record", record_uid);
        return true;
    }

    return false;
}

static bool add_new_record(struct failure_record_uid_t *record_uid)
{
    struct fail_record_t *node = NULL;

    if (g_fail_record_num >= MAX_RECORD_LIST_NUM) {
        tloge("add record: the number of list node is overstepped\n");
        return false;
    }

    node = (struct fail_record_t *)TEE_Malloc(sizeof(*node), 0);
    if (node == NULL) {
        tloge("add_fail_record malloc failed\n");
        return false;
    }

    errno_t rc = memcpy_s(&(node->record_uid), sizeof(node->record_uid),
                          record_uid, sizeof(*record_uid));
    if (rc != EOK)
        tlogw("mem copy fail!");

    print_record("add fail record", record_uid);
    dlist_insert_tail(&node->fail_record_head, &g_fail_record_list);
    g_fail_record_num++;

    return true;
}

bool add_fail_record(struct failure_record_uid_t *record_uid, bool init_flag)
{
    if (!check_param_and_init_flag(record_uid))
        return false;

    if (gk_mutex_lock_ops(&g_list_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return false;
    }

    if (find_and_update(record_uid, init_flag)) {
        (void)pthread_mutex_unlock(&g_list_mutex);
        return true;
    }

    bool ret = add_new_record(record_uid);
    (void)pthread_mutex_unlock(&g_list_mutex);

    return ret;
}

static bool read_fail_record_v3(struct failure_record_uid_t *record_uid)
{
    struct fail_record_t *node = NULL;

    node = get_list_node_v3(record_uid->record.secure_user_id, record_uid->version);
    if (node != NULL) {
        errno_t rc = memcpy_s(record_uid, sizeof(*record_uid),
                              &(node->record_uid), sizeof(node->record_uid));
        if (rc != EOK)
            tlogw("mem copy fail!");

        print_record("read fail record", record_uid);
        return true;
    }

    tlogd("read record not found: uid:%u, version:%u secure_user_id 0x%llx ",
          record_uid->uid, record_uid->version, record_uid->record.secure_user_id);
    return false;
}

static bool read_fail_record_v5(struct failure_record_uid_t *record_uid)
{
    struct fail_record_t *node = NULL;

    node = get_list_node_v5(record_uid->uid, record_uid->version);
    if (node != NULL) {
        errno_t rc = memcpy_s(record_uid, sizeof(*record_uid),
                              &(node->record_uid), sizeof(node->record_uid));
        if (rc != EOK)
            tlogw("mem copy fail!");

        print_record("read fail record", record_uid);
        return true;
    }

    tlogd("read record not found: uid:%u, version:%u secure_user_id 0x%llx ",
          record_uid->uid, record_uid->version, record_uid->record.secure_user_id);
    return false;
}

bool read_fail_record(struct failure_record_uid_t *record_uid)
{
    bool ret = false;

    if (!check_param_and_init_flag(record_uid))
        return false;

    if (gk_mutex_lock_ops(&g_list_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return false;
    }

    if (record_uid->version < HANDLE_VERSION_5)
        ret = read_fail_record_v3(record_uid);
    else
        ret = read_fail_record_v5(record_uid);

    (void)pthread_mutex_unlock(&g_list_mutex);
    return ret;
}

static bool write_fail_record_v3(const struct failure_record_uid_t *record_uid)
{
    struct fail_record_t *node = NULL;
    struct failure_record_uid_t *node_record = NULL;

    node = get_list_node_v3(record_uid->record.secure_user_id, record_uid->version);
    if (node != NULL) {
        node_record = &(node->record_uid);
        node_record->record.last_checked_timestamp = record_uid->record.last_checked_timestamp;
        node_record->record.failure_counter = record_uid->record.failure_counter;
        print_record("write fail record v3", record_uid);
        return true;
    }

    return false;
}

static bool write_fail_record_v5(const struct failure_record_uid_t *record_uid)
{
    struct fail_record_t *node = NULL;
    struct failure_record_uid_t *node_record = NULL;

    node = get_list_node_v5(record_uid->uid, record_uid->version);
    if (node != NULL) {
        node_record = &(node->record_uid);
        if (node_record->record.secure_user_id != record_uid->record.secure_user_id ||
            TEE_MemCompare(node_record->signature, record_uid->signature, HMAC_SIZE) != 0) {
            tloge("record sid or signature is wrong!");
            return false;
        }
        node_record->record.last_checked_timestamp = record_uid->record.last_checked_timestamp;
        node_record->record.failure_counter = record_uid->record.failure_counter;
        print_record("write fail record v5", record_uid);
        return true;
    }

    return  false;
}

bool write_fail_record(const struct failure_record_uid_t *record_uid)
{
    bool ret = false;

    if (check_param_and_init_flag(record_uid) == false)
        return false;

    tlogd("write record enter");

    if (gk_mutex_lock_ops(&g_list_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return false;
    }

    if (record_uid->version < HANDLE_VERSION_5)
        ret = write_fail_record_v3(record_uid);
    else
        ret = write_fail_record_v5(record_uid);

    (void)pthread_mutex_unlock(&g_list_mutex);
    return ret;
}

bool read_primary_fail_record(struct failure_record_uid_t *primary_record)
{
    struct fail_record_t *node = NULL;
    dlist_for_each_entry(node, &g_fail_record_list, struct fail_record_t, fail_record_head) {
        if (node->record_uid.version < HANDLE_VERSION_5)
            continue;

        if (node->record_uid.uid == PRIMARY_FAKE_USER_ID) {
            errno_t rc = memcpy_s(primary_record, sizeof(*primary_record),
                                  &(node->record_uid), sizeof(node->record_uid));
            if (rc != EOK) {
                tloge("mem copy fail!");
                break;
            }
            return true;
        }
    }

    return false;
}

bool read_sub_user_fail_record(struct failure_record_uid_t *record_array, uint32_t *array_size)
{
    struct fail_record_t *node = NULL;
    uint32_t index = 0;

    if (!g_init_flag) {
        tloge("read all record: list is not initialized\n");
        return false;
    }

    if (array_size == NULL) {
        tloge("null pointer for array size\n");
        return false;
    }

    if (gk_mutex_lock_ops(&g_list_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return false;
    }

    dlist_for_each_entry(node, &g_fail_record_list, struct fail_record_t, fail_record_head) {

        if (node->record_uid.version < HANDLE_VERSION_5 ||
            node->record_uid.uid == PRIMARY_FAKE_USER_ID)
            continue;

        if (record_array != NULL) {
            if (index >= *array_size / sizeof(*record_array))
                goto unlock;

            errno_t rc = memcpy_s(&(record_array[index]), sizeof(record_array[index]),
                                  &(node->record_uid), sizeof(node->record_uid));
            if (rc != EOK) {
                tloge("mem copy fail!");
                continue;
            }
            print_record("read sub users fail record", &(record_array[index]));
        }

        index++;
    }

    *array_size = index * sizeof(struct failure_record_uid_t);
    tlogd("read sub user record: Output buffer size is %u\n", *array_size);

unlock:
    (void)pthread_mutex_unlock(&g_list_mutex);
    return true;
}

bool delete_fail_record(const struct failure_record_uid_t *record_uid)
{
    struct fail_record_t *node = NULL;
    if (!check_param_and_init_flag(record_uid))
        return false;

    if (gk_mutex_lock_ops(&g_list_mutex) != 0) {
        tloge("pthread_mutex_lock failed\n");
        return false;
    }

    if (record_uid->version < HANDLE_VERSION_5)
        node = get_list_node_v3(record_uid->record.secure_user_id, record_uid->version);
    else
        node = get_list_node_v5(record_uid->uid, record_uid->version);

    if (node != NULL) {
        tlogd("find uid 0x%llx in list, delete it\n", record_uid->uid);
        dlist_delete(&node->fail_record_head);
        if (g_fail_record_num != 0)
            g_fail_record_num--;
        TEE_Free(node);
        node = NULL;
        (void)pthread_mutex_unlock(&g_list_mutex);
        return true;
    }

    (void)pthread_mutex_unlock(&g_list_mutex);
    return false;
}
