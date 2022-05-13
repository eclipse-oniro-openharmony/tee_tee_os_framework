/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: some functions declaration in config
 * Create: 2022-04-27
 */
#ifndef GTASK_CONFIG_H
#define GTASK_CONFIG_H
#include <stdint.h>
int get_tee_disable_ca_auth(void);
uint32_t get_tee_audit_event_enabled(void);

/* for builtin task */
uint32_t get_teeos_builtin_task_nums(void);
const struct task_info_st *get_teeos_builtin_task_infos(void);

/* for service property */
uint32_t get_teeos_service_property_num(void);
const struct ta_property *get_teeos_service_property_config(void);

/* for spawn whitelist */
uint32_t get_spawn_list_num(void);
const char **get_spawn_whitelist(void);

#endif