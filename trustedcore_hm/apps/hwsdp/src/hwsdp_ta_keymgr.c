/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: This file contains the key manager required definitions for TEE
 * Author: Huzhonghua h00440650
 * Create: 2020-10-19
 */

#include "tee_log.h"
#include "tee_ext_api.h"
#include "tee_mem_mgmt_api.h"
#include "hwsdp_ta_keymgr.h"

#define KEY_TYEP(idx) (1u << (idx))
#define ISEC_KEY_DEFAULT_UID -1

isec_key_mgr_blk *g_isec_key_manager_blk[MAX_USER_NUMBER] = {NULL};
uint32_t g_isec_key_manager_blk_cnt = 0u;

typedef struct {
    uint8_t *data; /* key data pointer */
    uint32_t type; /* type of key */
    uint32_t len; /* key length */
    uint32_t bufsz; /* key data buffer size */
} hwsdp_isec_key;

static int32_t get_key_mgr_blk_idx_by_userid(int32_t user_id)
{
    int32_t i;

    for (i = 0; i < MAX_USER_NUMBER; i++) {
        if (((user_id == ISEC_KEY_DEFAULT_UID) &&
            (g_isec_key_manager_blk[i] == NULL)) ||
            ((g_isec_key_manager_blk[i] != NULL) &&
            (g_isec_key_manager_blk[i]->user_id == user_id))) {
            return i;
        }
    }
    return MAX_USER_NUMBER;
}

/*
 * Initialize isec key manager, this called by HWDPS tee starting.
 */
static int32_t create_isec_key_mgr_blk(int32_t user_id, int32_t *new_idx)
{
    isec_key_mgr_blk *blk_ptr = NULL;
    int32_t idx;

    if (g_isec_key_manager_blk_cnt >= MAX_USER_NUMBER)
        return HWSDP_TEE_USER_NUMBER_ERR;

    blk_ptr = (isec_key_mgr_blk *)TEE_Malloc(sizeof(isec_key_mgr_blk), 0u);
    if (blk_ptr == NULL)
        return HWSDP_TEE_MEMORY_ALLOC_ERR;

    idx = get_key_mgr_blk_idx_by_userid(ISEC_KEY_DEFAULT_UID);
    g_isec_key_manager_blk[idx] = blk_ptr;
    g_isec_key_manager_blk[idx]->user_id = user_id;
    *new_idx = idx;
    return HWSDP_TEE_SUCCESS;
}

static void release_isec_key_mgr_blk(int32_t blk_idx)
{
    g_isec_key_manager_blk[blk_idx]->user_id = ISEC_KEY_DEFAULT_UID;
    TEE_Free((void *)g_isec_key_manager_blk[blk_idx]);
    g_isec_key_manager_blk[blk_idx] = NULL;
    --g_isec_key_manager_blk_cnt;
    return;
}

void destroy_isec_key_all_mgr_blk(void)
{
    int32_t i;

    for (i = 0; (uint32_t)i < g_isec_key_manager_blk_cnt; i++) {
        if (g_isec_key_manager_blk[i] != NULL)
            release_isec_key_mgr_blk(i);
    }
    return;
}

static hwsdp_data_info **get_isec_key_cache_by_type(int32_t blk_idx, uint32_t key_type)
{
    int32_t i;

    i = get_first_true_bit_idx(key_type);
    if ((i == BITMAP_MAX_INDEX) || (i >= ISEC_KEY_MAX_NUM))
        return NULL;

    return (g_isec_key_manager_blk[blk_idx]->key + i);
}

static int32_t parse_key_from_data_buff(hwsdp_isec_key *user_key, uint8_t *data, uint32_t data_len)
{
    uint32_t offset;

    offset = 0u;
    if (sizeof(user_key->len) > data_len)
        return 0u;

    HWSDP_GET_4BYTE(user_key->len, data, offset);

    if ((user_key->len == 0) || ((sizeof(user_key->type) + offset) > data_len))
        return 0u;

    HWSDP_GET_4BYTE(user_key->type, data, offset);

    if ((user_key->len + offset) > data_len)
        return 0u;

    user_key->data = data + offset;
    user_key->bufsz = user_key->len;
    return (user_key->len + offset);
}

static int32_t store_isec_key_data(int32_t blk_idx, int32_t key_num, uint8_t *data, uint32_t data_len)
{
    int32_t i;
    int32_t ret;
    hwsdp_data_info **key_cache = NULL;
    hwsdp_isec_key user_key;
    uint32_t offset;
    uint32_t len;

    offset = 0u;
    len = 0u;
    for (i = 0; i < key_num; i++) {
        len = parse_key_from_data_buff(&user_key, data + offset, data_len - offset);
        if (len == 0u)
            return HWSDP_TEE_KEY_LENGTH_ERR;

        offset += len;
        key_cache = get_isec_key_cache_by_type(blk_idx, user_key.type);
        if (key_cache == NULL)
            return HWSDP_TEE_KEY_INFORMATION_ERR;

        if (*key_cache == NULL) {
            *key_cache = (hwsdp_data_info *)TEE_Malloc(sizeof(hwsdp_data_info), 0u);
            if (*key_cache == NULL)
                return HWSDP_TEE_MEMORY_ALLOC_ERR;

        }
        ret = hwsdp_store_data(*key_cache, (const uint8_t *)(user_key.data), user_key.len);
        if (ret != HWSDP_TEE_SUCCESS)
            return ret;

        (g_isec_key_manager_blk[blk_idx]->num)++;
    }
    return HWSDP_TEE_SUCCESS;
}

/*
 * add an isec key to key manager. this called in 
 * if added success, return HWSDP_SUCCESS, else return the error code.
 */
int32_t isec_add_key_data(uint32_t param_types, TEE_Param *params, uint32_t param_num)
{
    uint8_t *data = NULL;
    uint32_t data_len;
    uint32_t offset;
    int32_t user_id;
    int32_t idx;
    int32_t ret;
    uint32_t key_num;

    PARAM_NOT_USED(param_types);
    PARAM_NOT_USED(param_num);

    data = (uint8_t *)(params[0].memref.buffer);
    data_len = params[0].memref.size;
    offset = (uint32_t)sizeof(hwsdp_msghdr);
    HWSDP_GET_4BYTE(user_id, data, offset);
    if (user_id < 0)
        return HWSDP_TEE_USER_ID_ERR;

    HWSDP_GET_4BYTE(key_num, data, offset);
    if (key_num == 0u)
        return HWSDP_TEE_KEY_NUMBER_ERR;

    idx = get_key_mgr_blk_idx_by_userid(user_id);
    if (idx == MAX_USER_NUMBER) {
        ret = create_isec_key_mgr_blk(user_id, &idx);
        SLogTrace("create_isec_key_mgr_blk with user_id[%d], ret %d", user_id, ret);
        if (ret != HWSDP_TEE_SUCCESS)
            return ret;

        ++g_isec_key_manager_blk_cnt;
    }

    ret = store_isec_key_data(idx, key_num, data + offset, data_len - offset);
    SLogTrace("isec_add_key_data done user_id[%d], ret %d", user_id, ret);
    return ret;
}

static void del_isec_key_data(int32_t idx, uint32_t key_type_set)
{
    int32_t i;
    isec_key_mgr_blk *mgr_blk = NULL;

    if (g_isec_key_manager_blk[idx] == NULL)
        return;

    mgr_blk = g_isec_key_manager_blk[idx];
    for (i = 0; i < ISEC_KEY_MAX_NUM; i++) {
        if (((key_type_set >> i) & 0x01u) && (mgr_blk->key[i] != NULL)) {
            hwsdp_release_data_buffer(mgr_blk->key[i]);
            mgr_blk->num--;
        }
    }
    return;
}

/*
 * delete an isec key from key manager.
 * if added success, return HWSDP_SUCCESS, else return the error code.
 */
int32_t isec_del_key_data(uint32_t param_types, TEE_Param *params, uint32_t param_num)
{
    uint8_t *buff = NULL;
    uint32_t offset;
    int32_t user_id;
    uint32_t key_type_set;
    int32_t idx;

    (void)param_types;
    (void)param_num;

    buff = (uint8_t *)(params[0].memref.buffer);
    offset = (uint32_t)sizeof(hwsdp_msghdr);
    HWSDP_GET_4BYTE(user_id, buff, offset);
    idx = get_key_mgr_blk_idx_by_userid(user_id);
    if ((user_id < 0) || (idx == MAX_USER_NUMBER))
        return HWSDP_TEE_USER_ID_ERR;

    HWSDP_GET_4BYTE(key_type_set, buff, offset);
    del_isec_key_data(idx, key_type_set);
    if (g_isec_key_manager_blk[idx]->num == 0u)
        release_isec_key_mgr_blk(idx);

    return HWSDP_TEE_SUCCESS;
}

static int32_t get_key_to_user_buffer(int32_t blk_idx, uint32_t key_set, uint8_t *buff, uint32_t bufsz)
{
    int32_t n;
    int32_t idx;
    uint32_t *len_ptr = NULL;
    uint32_t *type_ptr = NULL;
    uint32_t tmp_set;
    uint32_t offset;
    isec_key_mgr_blk *key_mgr_blk = NULL;

    /* ensure the key buffer is correct */
    if ((bufsz == 0u) || (buff == NULL))
        return 0;

    offset = 0u;
    tmp_set = key_set;
    key_mgr_blk = g_isec_key_manager_blk[blk_idx];
    while (tmp_set > 0) {
        idx = get_first_true_bit_idx(tmp_set);
        if (idx == BITMAP_MAX_INDEX)
            break;

        n = 0;
        type_ptr = (uint32_t *)(buff + offset + n);
        n += sizeof(uint32_t);
        len_ptr = (uint32_t *)(buff + offset + n);
        n += sizeof(uint32_t);
        *len_ptr = hwsdp_copy_data(key_mgr_blk->key[idx], buff + offset + n, bufsz - offset - n);
        if (*len_ptr > 0u) {
            *type_ptr = KEY_TYEP(idx);
            offset += (n + *len_ptr);
        }
        tmp_set &= ~(1u << idx);
    }
    return offset;
}

/*
 * get an isec key from key manager, if key is cipher, must call DecryptKeyDataByHuk to decrypt the key.
 * if get success, return HWSDP_SUCCESS, else return the error code.
 */
int32_t isec_get_key_data(uint32_t param_types, TEE_Param *params, uint32_t param_num)
{
    uint8_t *buff = NULL;
    uint32_t offset;
    uint32_t key_set;
    int32_t user_id;
    int32_t out_key_num;
    int32_t idx;

    (void)param_num;
    /* 1 - the second parameter of params, 2 - the third parameter of params */
    if ((TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT) &&
        (TEE_PARAM_TYPE_GET(param_types, 2) != TEE_PARAM_TYPE_VALUE_OUTPUT)) {
        return HWSDP_TEE_BAD_PARAMETER;
    }

    buff = (uint8_t *)(params[0].memref.buffer);
    offset = (uint32_t)sizeof(hwsdp_msghdr);
    HWSDP_GET_4BYTE(user_id, buff, offset);
    idx = get_key_mgr_blk_idx_by_userid(user_id);
    if (idx == MAX_USER_NUMBER) {
        SLogWarning("isec_get_key_data, user[%d] data is empty", user_id);
        return HWSDP_TEE_SUCCESS;
    }
    HWSDP_GET_4BYTE(out_key_num, buff, offset);
    if (out_key_num <= 0) {
        params[2].value.a = 0;
        return HWSDP_TEE_KEY_NUMBER_ERR;
    }
    HWSDP_GET_4BYTE(key_set, buff, offset);
    /* 1 - the second parameter of params, 2 - the third parameter of params */
    params[2].value.a = get_key_to_user_buffer(idx, key_set,
        (uint8_t *)(params[1].memref.buffer), params[1].memref.size);
    return HWSDP_TEE_SUCCESS;
}

hwsdp_msghandler get_isec_key_handler_by_opcode(int32_t op_code)
{
    hwsdp_msghandler_map msg_handler_map[HWSDP_OPS_MAX_CODE] = {
        {isec_add_key_data, HWSDP_OPS_ADD_ISEC_KEY},
        {isec_del_key_data, HWSDP_OPS_DEL_ISEC_KEY},
        {isec_get_key_data, HWSDP_OPS_GET_ISEC_KEY}
    };

    if (msg_handler_map[op_code].op_code != op_code)
        return NULL;

    return msg_handler_map[op_code].msg_handler;
}
