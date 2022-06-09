/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: some functions declaration in config
 * Create: 2022-04-21
 */

#ifndef GTASK_CONFIG_HAL_H
#define GTASK_CONFIG_HAL_H
#include <ta_framework.h>

bool ta_no_uncommit(const TEE_UUID *uuid);
bool ta_vsroot_flush(const TEE_UUID *uuid);

int is_in_spawnlist(const char *name);
const struct rsv_mem_pool_uuid_item *get_rsv_mem_item(uint64_t paddr, uint32_t size, uint32_t type);
bool is_ext_agent(uint32_t agent_id);
bool check_ext_agent_permission(const TEE_UUID *uuid, uint32_t agent_id);
uint32_t get_build_in_services_property(const TEE_UUID *uuid, struct ta_property *property);
bool is_build_in_service(const TEE_UUID *uuid);
const struct task_info_st *get_builtin_task_info_by_index(uint32_t index);
uint32_t get_builtin_task_nums(void);

#endif
