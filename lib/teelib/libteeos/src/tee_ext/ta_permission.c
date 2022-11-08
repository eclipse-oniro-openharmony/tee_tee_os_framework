/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "ta_permission.h"
#include <stdint.h>
#include <stdlib.h>
#include <sre_access_control.h>
#include <ac.h>
#include <sys/mman.h>
#include <tee_log.h>
#include "ac_map.h"
#include "ta_framework.h"
#include "tee_config.h"

#define DYNAMIC_TA_PERM_SIZE 32
#define DYNAMIC_TA_RESV_SIZE 16

static const uint64_t g_native_ta_permission[] = {
    [AC_UID_IDX_SUPER]     = ALL_GROUP_PERMISSION,
    [AC_UID_IDX_TALDR]     = CC_RNG_GROUP_PERMISSION,
    [AC_UID_IDX_GTASK]     = GT_PERMISSIONS | TZASC_GROUP_PERMISSION | TIMER_GROUP_PERMISSION,
    [AC_UID_IDX_DRV_TIMER] = CC_RNG_GROUP_PERMISSION | TIMER_GROUP_PERMISSION,
    [AC_UID_IDX_STORAGE]   = CC_RNG_GROUP_PERMISSION | GENERAL_GROUP_PERMISSION,
};

const uint32_t g_dynamic_native_ta_num = sizeof(g_native_ta_permission) / sizeof(g_native_ta_permission[0]);

uint64_t *g_ta_permission = NULL;

static TEE_Result fill_ta_permission(uint32_t num)
{
    uint32_t dynamic_ta_num = get_dynamic_ta_num();
    uint32_t i;
    const uid_t *ta_uid = NULL;
    uint32_t uuid_num;
    uuid_num = (uint32_t)ac_get_uuid_max();
    if (num > uuid_num)
        return TEE_ERROR_BAD_PARAMETERS;

    if (g_ta_permission == NULL) {
        tloge("g_ta_permission null");
        return TEE_ERROR_GENERIC;
    }

    for (i = 0; i < dynamic_ta_num; i++) {
        const struct ta_permission *ta_permission_config = get_permission_config_by_index(i);
        if (ta_permission_config == NULL)
            continue;
        ta_uid = ac_uuid_to_uid(&ta_permission_config->uuid);
        if (ta_uid == NULL) {
            tloge("ac_uuid_to_uid failed\n");
            return TEE_ERROR_NOT_SUPPORTED;
        }

        if (*ta_uid < AC_TA_UID_BASE || *ta_uid >= num + AC_TA_UID_BASE)
            continue;
        g_ta_permission[*ta_uid - AC_TA_UID_BASE] = ta_permission_config->permissions;
    }

    return TEE_SUCCESS;
}

static uint32_t g_dyn_perm_size      = DYNAMIC_TA_PERM_SIZE;
static uint64_t *g_dyn_ta_permission = NULL;

static TEE_Result dyn_perm_array_init(void)
{
    if (g_dyn_perm_size == 0)
        return TEE_ERROR_GENERIC;
    g_dyn_ta_permission = malloc(sizeof(uint64_t) * g_dyn_perm_size);
    if (g_dyn_ta_permission == NULL) {
        tloge("malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    for (uint32_t i = 0; i < g_dyn_perm_size; i++)
        g_dyn_ta_permission[i] = GENERAL_GROUP_PERMISSION;

    return TEE_SUCCESS;
}

static bool is_over_flow(uint32_t num1, uint32_t num2)
{
    if (num1 == 0 || num2 == 0)
        return false;
    if (((num1 * num2) / num2) != num1)
        return true;
    return false;
}

static TEE_Result extend_dyn_perm_array(uint32_t sz)
{
    uint64_t *p = NULL;
    uint32_t mem_sz;

    if (sz <= g_dyn_perm_size) {
        tloge("try to reduce g_dyn_ta_permission array\n");
        return TEE_ERROR_GENERIC;
    }

    if (g_dyn_ta_permission == NULL) {
        tloge("g_dyn_ta_permission null");
        return TEE_ERROR_GENERIC;
    }

    if (is_over_flow(sz, sizeof(uint64_t))) {
        tloge("sz is too large!");
        return TEE_ERROR_GENERIC;
    }
    mem_sz = sz * sizeof(uint64_t);
    p      = malloc(mem_sz);
    if (p == NULL) {
        tloge("malloc failed %u\n", sz);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    for (uint32_t i = 0; i < g_dyn_perm_size; i++)
        p[i] = g_dyn_ta_permission[i];

    for (uint32_t i = g_dyn_perm_size; i < sz; i++)
        p[i] = GENERAL_GROUP_PERMISSION;

    free(g_dyn_ta_permission);
    g_dyn_ta_permission = p;
    g_dyn_perm_size     = sz;

    return TEE_SUCCESS;
}

TEE_Result add_ta_permission(const TEE_UUID *uuid, uint64_t permissions)
{
    uid_t uid;
    TEE_Result ret;
    uint32_t uuid_num = (uint32_t)ac_get_uuid_max();

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
    if (g_ta_permission == NULL || g_dyn_ta_permission == NULL) {
        tloge("g_ta_permission or g_dyn_ta_permission null");
        return TEE_ERROR_GENERIC;
    }

    if (ac_uuid_to_uid_sync(uuid, &uid) != 0) {
        tloge("ac_uuid_to_uid_sync failed uuid:%08x\n", uuid->timeLow);
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    if (uid >= AC_TA_UID_BASE && uid < AC_TA_UID_BASE + uuid_num) {
        g_ta_permission[uid - AC_TA_UID_BASE] = permissions;
        return TEE_SUCCESS;
    }

    if (uid < AC_DYN_UID_BASE) {
        tloge("invalid uid\n");
        return TEE_ERROR_GENERIC;
    }

    if (uid - AC_DYN_UID_BASE >= g_dyn_perm_size) {
        ret = extend_dyn_perm_array(uid - AC_DYN_UID_BASE + DYNAMIC_TA_RESV_SIZE);
        if (ret != TEE_SUCCESS)
            return ret;
    }

    g_dyn_ta_permission[uid - AC_DYN_UID_BASE] = permissions;

    return TEE_SUCCESS;
}

int ta_permission_init(void)
{
    uint32_t size, uuid_num;
    TEE_Result ret;

    uuid_num = (uint32_t)ac_get_uuid_max();
    size     = uuid_num * sizeof(uint64_t);

    if (size == 0)
        return (int)TEE_ERROR_GENERIC;
    g_ta_permission = malloc(size);
    if (g_ta_permission == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;
    for (uint32_t i = 0; i < uuid_num; i++)
        g_ta_permission[i] = GENERAL_GROUP_PERMISSION;

    ret = fill_ta_permission(uuid_num);
    if (ret != TEE_SUCCESS)
        goto failed;

    ret = dyn_perm_array_init();
    if (ret != TEE_SUCCESS)
        goto failed;

    return (int)TEE_SUCCESS;
failed:
    free(g_ta_permission);
    g_ta_permission = NULL;
    return (int)ret;
}

TEE_Result get_ta_permission_wrapper(uid_t uid, uint64_t *permissions)
{
    if (permissions == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (uid < g_dynamic_native_ta_num) {
        *permissions = g_native_ta_permission[uid];
        return TEE_SUCCESS;
    }

    if (uid >= AC_DYN_UID_BASE && uid < AC_DYN_UID_BASE + g_dyn_perm_size) {
        *permissions = g_dyn_ta_permission[uid - AC_DYN_UID_BASE];
        return TEE_SUCCESS;
    }

    if (uid < AC_TA_UID_BASE || uid >= (uint32_t)ac_get_uuid_max() + AC_TA_UID_BASE) {
        *permissions = GENERAL_GROUP_PERMISSION;
        return TEE_SUCCESS;
    }

    if (g_ta_permission == NULL) {
        tloge("g_ta_permission null");
        return TEE_ERROR_GENERIC;
    }

    *permissions = g_ta_permission[uid - AC_TA_UID_BASE];

    return TEE_SUCCESS;
}
