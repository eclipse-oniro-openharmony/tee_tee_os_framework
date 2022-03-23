/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: product configs
 * Author: w00414120 wangzhuochen1@huawei.com
 * Create: 2020-03-10
 */

#include <sys/hm_priorities.h> /* for `HM_PRIO_TEE_*` */
#include "tee_config.h"
#include "sre_access_control.h"
#include "product_uuid.h"
#include "product_uuid_public.h"
#include "task_name.h"

/* should be kept consistent with DTS */
const struct rsv_mem_pool_uuid_item g_rsv_mem_pool_configs[] = {

};

const uint32_t g_rsv_mem_pool_num = sizeof(g_rsv_mem_pool_configs) / sizeof(g_rsv_mem_pool_configs[0]);

#ifdef CONFIG_AUTH_ENHANCE
struct call_info g_kernel_ca_whitelist[] = {
#if TEE_SUPPORT_HSM
    { "hsm-ca", true, 0, INVALID_PID, TEE_SERVICE_HSM_BBOX },
#endif
    { "hsm-ca-update-firmware", true, 0, INVALID_PID, TEE_SERVICE_HSM_UPGRADE },
    { "hsm-ca-efuse-flash", true, 0, INVALID_PID, TEE_SERVICE_HSM_EFUSE },
    { "hsm-ca-flash", true, 0, INVALID_PID, TEE_SERVICE_HSM_FLASH },
    { "hsm-ca-fuzz-test", true, 0, INVALID_PID, TEE_SERVICE_HSM_BBOX },
    { "hsm-ca-fuzz-test", true, 0, INVALID_PID, TEE_SERVICE_HSM_UPGRADE },
    { "hsm-ca-fuzz-test", true, 0, INVALID_PID, TEE_SERVICE_HSM_EFUSE },
    { "hsm-ca-fuzz-test", true, 0, INVALID_PID, TEE_SERVICE_HSM_FLASH },
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
#if TEE_SUPPORT_HSM
    { TEE_SERVICE_HSM, HSM_TASK_NAME, "/hsm.elf", HM_PRIO_TEE_AGENT, true },
    { TEE_SERVICE_HSM_BBOX, HSM_BBOX_NAME, "/hsm_bbox.elf", HM_PRIO_TEE_TA, true },
#endif
#ifdef TEE_SUPPORT_KMS
    { TEE_SERVICE_KMS, KMS_TASK_NAME, "/kms.elf", HM_PRIO_TEE_TA, true },
#endif
    { TEE_SERVICE_HSM_UPGRADE, HSM_UPGRADE_NAME, "/firmware_upgrade.elf", HM_PRIO_TEE_TA, true },
    { TEE_SERVICE_HSM_EFUSE, HSM_EFUSE_NAME, "/hsm_efuse.elf", HM_PRIO_TEE_TA, true },
    { TEE_SERVICE_HSM_FLASH, HSM_FLASH_NAME, "/hsm_flash.elf", HM_PRIO_TEE_TA, true },
#ifdef TEE_SUPPORT_PERM_64BIT
    { TEE_SERVICE_PERM, PERM_SERVICE_NAME,      "/permission_service.elf", HM_PRIO_TEE_AGENT, true },
#elif TEE_SUPPORT_PERM_32BIT
    { TEE_SERVICE_PERM, PERM_SERVICE_NAME,      "/permission_service.elf", HM_PRIO_TEE_AGENT, false },
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

/* build in service propertys for product */
#define KMS_STACK_SIZE (DEFAULT_STACK_SIZE * 5)
#define KMS_HEAP_SIZE (DEFAULT_HEAP_SIZE * 64)
#define STACK_PERM 8
#define HEAP_PERM  3
const struct ta_property g_product_service_property[] = {
    /* uuid  stack  heap  instance  multi_session alive ssa_enum_enable other_property other_property_len */
#ifdef TEE_SUPPORT_HSM
    { TEE_SERVICE_HSM, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
    { TEE_SERVICE_HSM_BBOX, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#endif
#ifdef TEE_SUPPORT_KMS
    { TEE_SERVICE_KMS, KMS_STACK_SIZE, KMS_HEAP_SIZE, true, true, true, false, "gpd.ta.api_level:3", 19 },
#endif
    { TEE_SERVICE_HSM_UPGRADE, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
    { TEE_SERVICE_HSM_EFUSE, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
    { TEE_SERVICE_HSM_FLASH, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
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
    /* internal tasks */
#ifdef TEE_SUPPORT_HSM
    { TEE_SERVICE_HSM, 0, HSM_GROUP_PERMISSION },
    { TEE_SERVICE_HSM_BBOX, 0, HSM_GROUP_PERMISSION },
#endif
#ifdef TEE_SUPPORT_KMS
    { TEE_SERVICE_KMS, 0, CC_KEY_GROUP_PERMISSION },
#endif
    { TEE_SERVICE_HSM_UPGRADE, 0, HSM_GROUP_PERMISSION | TIMER_GROUP_PERMISSION | HSM_EFUSE_GROUP_PERMISSION |
        FLASH_GROUP_PERMISSION},
    { TEE_SERVICE_HSM_EFUSE, 0, HSM_GROUP_PERMISSION | HSM_EFUSE_GROUP_PERMISSION },
    { TEE_SERVICE_HSM_FLASH, 0, HSM_GROUP_PERMISSION | FLASH_GROUP_PERMISSION },
    { TEE_SERVICE_PERM, 0, PERMSRV_GROUP_PERMISSION | OEM_KEY_GROUP_PERMISSION },
    { TEE_SERVICE_SSA, 0, FLASH_GROUP_PERMISSION },
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
