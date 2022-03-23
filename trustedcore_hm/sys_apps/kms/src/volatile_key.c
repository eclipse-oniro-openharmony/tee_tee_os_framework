/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: kms volatile key management
 * Author: chengfuxing@huawei.com
 * Create: 2021-12-7
 */

#include "volatile_key.h"
#include "securec.h"

static struct volatile_key g_vkeys[MAX_VOLATILE_KEY_COUNT];
static pthread_mutex_t g_vkeys_lock;
static bool g_vkeys_init_flag = false;

void destroy_vkey_list_lock(void)
{
    if (g_vkeys_init_flag) {
        if (pthread_mutex_destroy(&g_vkeys_lock) != 0) {
            tloge("destroy vkey list lock failed");
            return;
        }
        g_vkeys_init_flag = false;
    }
}

TEE_Result vkey_list_init(void)
{
    int32_t ret = pthread_mutex_init(&g_vkeys_lock, NULL);
    if (ret != 0) {
        tloge("vkey list init: lock init fail");
        return TEE_ERROR_GENERIC;
    }
    (void)memset_s(g_vkeys, sizeof(g_vkeys), 0x0, sizeof(g_vkeys));
    g_vkeys_init_flag = true;
    return TEE_SUCCESS;
}

static void free_volatile_key(struct volatile_key *v_key)
{
    if (v_key == NULL)
        return;
    (void)memset_s(v_key->key_id, sizeof(v_key->key_id), 0x0, sizeof(v_key->key_id));
    if (v_key->key_blob.buffer != NULL) {
        (void)memset_s(v_key->key_blob.buffer, v_key->key_blob.length, 0x0, v_key->key_blob.length);
        TEE_Free(v_key->key_blob.buffer);
        v_key->key_blob.buffer = NULL;
    }
    v_key->key_blob.length = 0;
}

static TEE_Result check_set_keyid_buff(const char *key_id, const char *init_key, char *key_id_buff, uint32_t key_id_len)
{
    if (key_id == NULL) {
        tloge("null ptr");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (strlen(key_id) > MAX_LENGTH || strlen(key_id) == 0 ||
        TEE_MemCompare(init_key, key_id, strlen(key_id)) == 0);
    if (check) {
        tloge("invalid key id len %u", strlen(key_id));
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memcpy_s(key_id_buff, key_id_len, key_id, strlen(key_id)) != EOK) {
        tloge("copy key id failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result check_insert_condition(const char *key_id, const char *init_key, char *key_id_buff,
    uint32_t key_id_len)
{
    TEE_Result ret = check_set_keyid_buff(key_id, init_key, key_id_buff, key_id_len);
    if (ret != TEE_SUCCESS) {
        tloge("check set keyid buff failed");
        return ret;
    }
    if (get_volatile_keyblob(key_id, NULL) == TEE_SUCCESS) {
        tloge("key id already exists");
        return TEE_ERROR_ACCESS_DENIED; /* existed key id should use this error code */
    }
    return TEE_SUCCESS;
}

TEE_Result insert_volatile_keyblob(const char *key_id, const struct kms_buffer_data *blob)
{
    bool check = (key_id == NULL || blob == NULL || blob->buffer == NULL || blob->length == 0);
    if (check) {
        tloge("null ptr");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t i;
    const char init_key[MAX_LENGTH] = {0};
    char key_id_buff[MAX_LENGTH] = {0};
    TEE_Result ret = check_insert_condition(key_id, init_key, key_id_buff, MAX_LENGTH);
    if (ret != TEE_SUCCESS)
        return ret;
    if (pthread_mutex_lock(&g_vkeys_lock) != 0) {
        tloge("insert vkey: lock fail");
        return TEE_ERROR_GENERIC;
    }
    for (i = 0; i < MAX_VOLATILE_KEY_COUNT; i++) {
        if (TEE_MemCompare(g_vkeys[i].key_id, init_key, sizeof(g_vkeys[i].key_id)) == 0 &&
            (g_vkeys[i].key_blob.buffer == NULL)) {
            g_vkeys[i].key_blob.buffer = TEE_Malloc(blob->length, TEE_MALLOC_FILL_ZERO);
            if (g_vkeys[i].key_blob.buffer == NULL) {
                tloge("malloc blob failed");
                (void)pthread_mutex_unlock(&g_vkeys_lock);
                return TEE_ERROR_OUT_OF_MEMORY;
            }
            g_vkeys[i].key_blob.length = blob->length;
            check = (memcpy_s(g_vkeys[i].key_blob.buffer, g_vkeys[i].key_blob.length,
                blob->buffer, blob->length) != EOK || memcpy_s(g_vkeys[i].key_id,
                sizeof(g_vkeys[i].key_id), key_id_buff, sizeof(key_id_buff)) != EOK);
            if (check) {
                tloge("insert volatile key blob failed");
                free_volatile_key(&g_vkeys[i]);
                (void)pthread_mutex_unlock(&g_vkeys_lock);
                return TEE_ERROR_GENERIC;
            }
            (void)pthread_mutex_unlock(&g_vkeys_lock);
            tlogd("insert volatile key %s success\n", key_id);
            return TEE_SUCCESS;
        }
    }
    if (pthread_mutex_unlock(&g_vkeys_lock) != 0) {
        tloge("insert vkey: unlock fail");
        return TEE_ERROR_GENERIC;
    }
    tloge("no volatile key space");
    return TEE_ERROR_STORAGE_NO_SPACE;
}

TEE_Result get_volatile_keyblob(const char *key_id, struct kms_buffer_data *out_blob)
{
    uint32_t i;
    char key_id_buff[MAX_LENGTH] = {0};
    const char init_key[MAX_LENGTH] = {0};

    TEE_Result ret = check_set_keyid_buff(key_id, init_key, key_id_buff, MAX_LENGTH);
    if (ret != TEE_SUCCESS) {
        tloge("get vkey: check set keyid buff failed");
        return ret;
    }
    for (i = 0; i < MAX_VOLATILE_KEY_COUNT; i++) {
        bool check = (TEE_MemCompare(g_vkeys[i].key_id, key_id_buff, sizeof(g_vkeys[i].key_id)) == 0 &&
            (g_vkeys[i].key_blob.buffer != NULL));
        if (check) {
            if (out_blob == NULL) /* only check whether the key is existed */
                return TEE_SUCCESS;
            if (out_blob->buffer == NULL || out_blob->length < g_vkeys[i].key_blob.length) {
                tloge("out blob buffer too short");
                return TEE_ERROR_SHORT_BUFFER;
            }
            if (memcpy_s(out_blob->buffer, out_blob->length, g_vkeys[i].key_blob.buffer,
                g_vkeys[i].key_blob.length) != EOK) {
                tloge("copy volatile key blob failed");
                return TEE_ERROR_GENERIC;
            }
            out_blob->length = g_vkeys[i].key_blob.length;
            return TEE_SUCCESS;
        }
    }
    return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result del_volatile_keyblob(const char *key_id)
{
    uint32_t i;
    char key_id_buff[MAX_LENGTH] = {0};
    const char init_key[MAX_LENGTH] = {0};

    TEE_Result ret = check_set_keyid_buff(key_id, init_key, key_id_buff, MAX_LENGTH);
    if (ret != TEE_SUCCESS) {
        tloge("delete vkey: check set keyid buff failed");
        return ret;
    }
    if (pthread_mutex_lock(&g_vkeys_lock) != 0) {
        tloge("delete vkey: lock fail");
        return TEE_ERROR_GENERIC;
    }
    for (i = 0; i < MAX_VOLATILE_KEY_COUNT; i++) {
        bool check = (TEE_MemCompare(g_vkeys[i].key_id, key_id_buff, sizeof(g_vkeys[i].key_id)) == 0 &&
            (g_vkeys[i].key_blob.buffer != NULL));
        if (check) {
            free_volatile_key(&g_vkeys[i]);
            if (pthread_mutex_unlock(&g_vkeys_lock) != 0) {
                tloge("delete vkey: unlock fail");
                return TEE_ERROR_GENERIC;
            }
            return TEE_SUCCESS;
        }
    }
    if (pthread_mutex_unlock(&g_vkeys_lock) != 0) {
        tloge("insert vkey: unlock fail");
        return TEE_ERROR_GENERIC;
    }
    tloge("volatile keyblob not found");
    return TEE_ERROR_ITEM_NOT_FOUND;
}

uint32_t count_volatile_key(void)
{
    uint32_t cnt = 0;
    uint32_t i;
    const char init_key_id[MAX_LENGTH] = {0};
    for (i = 0; i < MAX_VOLATILE_KEY_COUNT; i++) {
        bool check = (TEE_MemCompare(g_vkeys[i].key_id, init_key_id, sizeof(g_vkeys[i].key_id)) != 0 &&
            (g_vkeys[i].key_blob.buffer != NULL) && (g_vkeys[i].key_blob.length > 0));
        if (check)
            cnt++;
    }
    return cnt;
}

bool valid_key_id(const char *key_id)
{
    if (key_id == NULL) {
        tloge("null ptr");
        return false;
    }
    uint32_t len = strlen(key_id);
    if (len == 0 || len > MAX_KEY_ID_LEN) {
        tloge("invalid len %u", len);
        return false;
    }

    const char valid_chars[] = { '.', '_', '-' };
    uint32_t i;
    bool valid = false;
    for (i = 0; i < len; i++) {
        /* check char [a-zA-Z0-9] */
        valid = ((key_id[i] >= '0' && key_id[i] <= '9') || (key_id[i] >= 'a' && key_id[i] <= 'z') ||
            (key_id[i] >= 'A' && key_id[i] <= 'Z'));
        if (valid)
            continue;
        uint32_t j;
        for (j = 0; j < sizeof(valid_chars); j++) {
            /* check char ['.', '_', '-'] */
            valid = (key_id[i] == valid_chars[j]);
            if (valid)
                break;
        }
        if (!valid) {
            tloge("invalid char %c at %u", key_id[i], i);
            return false;
        }
    }
    return valid;
}
