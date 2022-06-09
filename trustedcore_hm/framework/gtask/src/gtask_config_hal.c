/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: gtask config implementation
 * Create: 2022-04-27
 */
#include "gtask_config_hal.h"
#include "gtask_config.h"
#include <autoconf.h>
#include <tee_mem_mgmt_api.h>
#include <tee_log.h>
#include <string.h>
#include <tee_config.h>
#include "gtask_config.h"
#include "product_config_hal.h"
#include "product_uuid_public.h"
#include "tee_inner_uuid.h"

static const TEE_UUID g_uncommit_whitelist[] = {
#ifndef SSA_SHRINK_MEMORY
    TEE_SERVICE_SSA,
#endif
    TEE_SERVICE_KEYMASTER,
    TEE_SERVICE_GATEKEEPER,
#ifdef TEE_SUPPORT_AI
    TEE_SERVICE_AI,
#endif
    TEE_SERVICE_PERM
};

static const TEE_UUID g_vsroot_flush_whitelist[] = {
#ifdef TEE_SUPPORT_AI
    TEE_SERVICE_AI
#endif
};

bool ta_no_uncommit(const TEE_UUID *uuid)
{
    if (uuid != NULL) {
        size_t nr = sizeof(g_uncommit_whitelist) / sizeof(TEE_UUID);
        for (size_t i = 0; i < nr; ++i) {
            if (!TEE_MemCompare(g_uncommit_whitelist + i, uuid, sizeof(TEE_UUID)))
                return true;
        }
    }
#ifdef MEMORY_NO_UC
    return true;
#else
    return false;
#endif
}

bool ta_vsroot_flush(const TEE_UUID *uuid)
{
    if (uuid == NULL)
        return false;
    size_t nr = sizeof(g_vsroot_flush_whitelist) / sizeof(TEE_UUID);
    if (nr == 0)
        return false;

    for (size_t i = 0; i < nr; ++i) {
        if (!TEE_MemCompare(g_vsroot_flush_whitelist + i, uuid, sizeof(TEE_UUID)))
            return true;
    }
    return false;
}


int is_in_spawnlist(const char *name)
{
    uint32_t i;
    const char **spawn_list = get_spawn_whitelist();
    uint32_t spawn_list_num = get_spawn_list_num();

    if (name == NULL) {
        tloge("invalid param name\n");
        return 0;
    }
    if (spawn_list == NULL)
        return 0;

    for (i = 0; i < spawn_list_num; i++) {
        if (spawn_list[i] == NULL)
            continue;
        if (strncmp(name, spawn_list[i], strlen(spawn_list[i]) + 1) == 0)
            return 1;
    }
    return 0;
}

/* next 3 functions for builtin task */
uint32_t get_builtin_task_nums(void)
{
    return get_product_builtin_task_num() + get_teeos_builtin_task_nums();
}

const struct task_info_st *get_builtin_task_info_by_index(uint32_t index)
{
    uint32_t builtin_task_num = get_builtin_task_nums();
    uint32_t teeos_builtin_nums = get_teeos_builtin_task_nums();
    const struct task_info_st *teeos_builtin_infos = NULL;
    const struct task_info_st *product_builtin_infos = NULL;

    if (index >= builtin_task_num)
        return NULL;

    if (index < teeos_builtin_nums) {
        teeos_builtin_infos = get_teeos_builtin_task_infos();
        if (teeos_builtin_infos == NULL)
            return NULL;
        return &teeos_builtin_infos[index];
    }

    product_builtin_infos = get_product_builtin_task_infos();
    if (product_builtin_infos == NULL)
        return NULL;
    return &product_builtin_infos[index - teeos_builtin_nums];
}

bool is_build_in_service(const TEE_UUID *uuid)
{
    uint32_t i;
    TEE_UUID global = TEE_SERVICE_GLOBAL;
    TEE_UUID reet = TEE_SERVICE_REET;
    uint32_t teeos_built_in_nums = get_teeos_builtin_task_nums();
    const struct task_info_st *teeos_builtin_infos = NULL;
    uint32_t product_builtin_task_num = get_product_builtin_task_num();
    const struct task_info_st *product_builtin_infos = NULL;

    if (uuid == NULL)
        return false;

    if (TEE_MemCompare(uuid, &global, sizeof(global)) == 0 ||
        TEE_MemCompare(uuid, &reet, sizeof(reet)) == 0)
        return true;

    for (i = 0; i < teeos_built_in_nums; i++) {
        teeos_builtin_infos = get_teeos_builtin_task_infos();
        if (teeos_builtin_infos == NULL)
            break;
        if (TEE_MemCompare(uuid, &(teeos_builtin_infos[i].uuid),
            sizeof(teeos_builtin_infos[0].uuid)) == 0)
            return true;
    }

    for (i = 0; i < product_builtin_task_num; i++) {
        product_builtin_infos = get_product_builtin_task_infos();
        if (product_builtin_infos == NULL)
            break;
        if (TEE_MemCompare(uuid, &(product_builtin_infos[i].uuid),
            sizeof(product_builtin_infos[0].uuid)) == 0)
            return true;
    }

    return false;
}

/* next 1 functions for service property */
uint32_t get_build_in_services_property(const TEE_UUID *uuid, struct ta_property *property)
{
    uint32_t i;
    uint32_t teeos_property_num = get_teeos_service_property_num();
    const struct ta_property *teeos_service_property = NULL;
    uint32_t product_property_num = get_product_service_property_num();
    const struct ta_property *product_service_property = NULL;

    if (uuid == NULL || property == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < product_property_num; i++) {
        product_service_property = get_product_service_property_config();
        if (product_service_property == NULL)
            break;
        if (TEE_MemCompare(uuid, &product_service_property[i].uuid, sizeof(TEE_UUID)) == 0) {
            *property = product_service_property[i];
            return TEE_SUCCESS;
        }
    }

    for (i = 0; i < teeos_property_num; i++) {
        teeos_service_property = get_teeos_service_property_config();
        if (teeos_service_property == NULL)
            break;
        if (TEE_MemCompare(uuid, &teeos_service_property[i].uuid, sizeof(TEE_UUID)) == 0) {
            *property = teeos_service_property[i];
            return TEE_SUCCESS;
        }
    }
    return TEE_ERROR_GENERIC;
}

bool is_ext_agent(uint32_t agent_id)
{
    uint32_t agent_item_num = get_ext_agent_item_num();
    const struct ext_agent_uuid_item *agent_item = get_ext_agent_whitelist();

    if (agent_item == NULL)
        return false;

    for (uint32_t i = 0; i < agent_item_num; i++) {
        if (agent_item[i].agent_id == agent_id)
            return true;
    }
    return false;
}

bool check_ext_agent_permission(const TEE_UUID *uuid, uint32_t agent_id)
{
    uint32_t agent_item_num = get_ext_agent_item_num();
    const struct ext_agent_uuid_item *agent_item = get_ext_agent_whitelist();

    if (agent_item == NULL)
        return false;

    for (uint32_t i = 0; i < agent_item_num; i++) {
        if ((TEE_MemCompare(uuid, &(agent_item[i].uuid), sizeof(*uuid)) == 0) &&
            (agent_item[i].agent_id == agent_id))
            return true;
    }
    return false;
}

const struct rsv_mem_pool_uuid_item *get_rsv_mem_item(uint64_t paddr, uint32_t size, uint32_t type)
{
    uint32_t item_num = get_rsv_mem_pool_config_num();
    const struct rsv_mem_pool_uuid_item *item = get_rsv_mem_pool_config();

    if (item == NULL)
        return NULL;

    for (uint32_t i = 0; i < item_num; ++i) {
        if (item[i].paddr == paddr &&
            item[i].size == size &&
            item[i].type == type)
            return &(item[i]);
    }
    return NULL;
}

