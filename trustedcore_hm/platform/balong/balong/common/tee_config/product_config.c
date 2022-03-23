/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: product configs
 * Author: w00414120 wangzhuochen1@huawei.com
 * Create: 2020-03-10
 */

#include "tee_config.h"
#include <sys/hm_priorities.h> /* for `HM_PRIO_TEE_*` */
#include "sre_access_control.h"
#include "product_uuid_public.h"
#include "product_uuid.h"

/* should be kept consistent with DTS */
const struct rsv_mem_pool_uuid_item g_rsv_mem_pool_configs[] = {

};

const uint32_t g_rsv_mem_pool_num = sizeof(g_rsv_mem_pool_configs) / sizeof(g_rsv_mem_pool_configs[0]);

#ifdef CONFIG_AUTH_ENHANCE
struct call_info g_kernel_ca_whitelist[] = {

};
const uint32_t g_kernel_ca_whitelist_num = sizeof(g_kernel_ca_whitelist) / sizeof(struct call_info);

uint32_t get_kernel_ca_whitelist_num(void)
{
    return g_kernel_ca_whitelist_num;
}

struct call_info *get_kernel_ca_whitelist(void)
{
    return g_kernel_ca_whitelist;
}
#endif

const char *g_hm_spawn_whitelist[] = {
#ifdef DEF_ENG
    "hm-teeos-test",  /* hm_tee_test */
#endif
};

const uint32_t g_hm_spawn_whitelist_num = sizeof(g_hm_spawn_whitelist) / sizeof(g_hm_spawn_whitelist[0]);

uint32_t get_spawn_list_num(void)
{
    return g_hm_spawn_whitelist_num;
}

const char **get_spawn_whitelist(void)
{
    return g_hm_spawn_whitelist;
}

const struct task_info_st g_product_builtin_task_infos[] = {
#ifdef TEE_SUPPORT_PERM_64BIT
    {TEE_SERVICE_PERM, PERM_SERVICE_NAME,      "/permission_service.elf", HM_PRIO_TEE_AGENT, true},
#elif TEE_SUPPORT_PERM_32BIT
    {TEE_SERVICE_PERM, PERM_SERVICE_NAME,      "/permission_service.elf", HM_PRIO_TEE_AGENT, false},
#endif
};
static const uint32_t g_product_builtin_task_num =
    sizeof(g_product_builtin_task_infos) / sizeof(g_product_builtin_task_infos[0]);

uint32_t get_product_builtin_task_num(void)
{
    return g_product_builtin_task_num;
}

const struct task_info_st *get_product_builtin_task_infos(void)
{
    return g_product_builtin_task_infos;
}

#define STACK_PERM 8
#define HEAP_PERM  3
/* build in service propertys for product */
const struct ta_property g_product_service_property[] = {
    { TEE_SERVICE_PERM, DEFAULT_STACK_SIZE * STACK_PERM, DEFAULT_HEAP_SIZE * HEAP_PERM,
      true, false, false, false, NULL, 0 },
};

static const uint32_t g_product_service_property_num =
    sizeof(g_product_service_property) / sizeof(g_product_service_property[0]);

uint32_t get_product_service_property_num(void)
{
    return g_product_service_property_num;
}

const struct ta_property *get_product_service_property_config(void)
{
    return g_product_service_property;
}

const struct ta_permission g_ta_permission_config[] = {
    { TEE_SERVICE_PERM, 0, PERMSRV_GROUP_PERMISSION | OEM_KEY_GROUP_PERMISSION },
};

static const uint32_t g_product_dynamic_ta_num = sizeof(g_ta_permission_config) / sizeof(g_ta_permission_config[0]);

uint32_t get_product_dynamic_ta_num(void)
{
    return g_product_dynamic_ta_num;
}

const struct ta_permission *get_product_ta_permission_config(void)
{
    return g_ta_permission_config;
}
