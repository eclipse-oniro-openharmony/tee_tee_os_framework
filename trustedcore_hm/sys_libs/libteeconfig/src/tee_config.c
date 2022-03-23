/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: functions to get configs
 * Create: 2020-03-10
 */
#include "tee_config.h"
#include <string.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include "platform_get.h"

int32_t get_tbac_info_by_name(const char *name, uint64_t *sid, uint64_t *job_type)
{
    uint32_t i;
    uint32_t nr = get_drv_frame_nums();
    const struct drv_frame_info *info_list = get_drv_frame_infos();

    if (name == NULL || sid == NULL || job_type == NULL) {
        tloge("bad params\n");
        return -1;
    }

    if (info_list == NULL) {
        tloge("no tbac info\n");
        return -1;
    }

    for (i = 0; i < nr; i++) {
        if (strncmp(name, info_list[i].drv_name, strlen(info_list[i].drv_name) + 1) == 0) {
            *sid = info_list[i].sid;
            *job_type = info_list[i].job_type;
            return 0;
        }
    }
    return -1;
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

uint32_t get_platform_die_id_size(void)
{
    uint32_t platform = 0;
    uint32_t chip     = 0;
    uint32_t die_size_num = get_die_id_size_num();
    const uint32_t *die_id_size = NULL;

    if (__get_platform_chip(&platform, &chip) != 0) {
        tloge("get platform failed\n");
        return INVALID_DIE_ID_SIZE;
    }

    die_id_size = get_tee_die_id_size();
    if (die_id_size == NULL)
        return INVALID_DIE_ID_SIZE;

#ifdef WITH_CHIP_DENVER
    if (chip == WITH_CHIP_DENVER)
        return DV_DIE_ID_SIZE;
#endif

    if (platform < die_size_num)
        return die_id_size[platform];
    return INVALID_DIE_ID_SIZE;
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

/* next 3 functions for permission config */
uint32_t get_dynamic_ta_num(void)
{
    return get_teeos_ta_permission_num() + get_product_dynamic_ta_num();
}

const struct ta_permission *get_permission_config_by_index(uint32_t num)
{
    uint32_t teeos_ta_num = get_teeos_ta_permission_num();
    const struct ta_permission *teeos_config = NULL;
    uint32_t product_ta_num = get_product_dynamic_ta_num();
    const struct ta_permission *product_config = NULL;

    if (num >= (teeos_ta_num + product_ta_num))
        return NULL;

    if (num < teeos_ta_num) {
        teeos_config = get_teeos_ta_permission_config();
        if (teeos_config == NULL)
            return NULL;
        return &(teeos_config[num]);
    }
    product_config = get_product_ta_permission_config();
    if (product_config == NULL)
        return NULL;
    return &product_config[num - teeos_ta_num];
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

const struct dynamic_mem_uuid_item *get_dyn_mem_item_by_configid(uint32_t configid)
{
    uint32_t item_num = get_dyn_mem_config_num();
    const struct dynamic_mem_uuid_item *item = get_dyn_mem_config();

    if (item == NULL)
        return NULL;

    for (uint32_t i = 0; i < item_num; i++) {
        if (item[i].configid == configid)
            return &(item[i]);
    }
    return NULL;
}

const struct dynamic_mem_uuid_item *get_dyn_mem_item_by_uuid(const TEE_UUID *uuid)
{
    uint32_t item_num = get_dyn_mem_config_num();
    const struct dynamic_mem_uuid_item *item = get_dyn_mem_config();

    if (item == NULL || uuid == NULL)
        return NULL;

    for (uint32_t i = 0; i < item_num; i++) {
        if (TEE_MemCompare(uuid, &(item[i].uuid), sizeof(*uuid)) == 0)
            return &(item[i]);
    }
    return NULL;
}
