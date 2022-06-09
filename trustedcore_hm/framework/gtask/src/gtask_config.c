/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: gtask configs
 * Create: 2022-04-27
 */
#include "gtask_config.h"
#include "tee_config.h"
#include <ac.h>
#include <security_ops.h>
#include <sys/hm_priorities.h> /* for HM_PRIO_TEE_* */
#include "tee_test_uuid.h"
#include "sre_access_control.h"

#ifdef TEE_DISABLE_CA_SIGN
const int g_tee_disable_ca_auth = TEE_DISABLE_CA_SIGN;
#else
const int g_tee_disable_ca_auth;
#endif

int get_tee_disable_ca_auth(void)
{
    return g_tee_disable_ca_auth;
}

const struct task_info_st g_teeos_builtin_task_infos[] = {
#ifdef TEE_SUPPORT_SSA_64BIT
    { TEE_SERVICE_SSA, SSA_SERVICE_NAME, "/ssa.elf", HM_PRIO_TEE_AGENT, true },
#elif TEE_SUPPORT_SSA_32BIT
    { TEE_SERVICE_SSA, SSA_SERVICE_NAME, "/ssa.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef TEE_SUPPORT_HUK_SERVICE_64BIT
    { TEE_SERVICE_HUK, HUK_TASK_NAME, "/huk_service.elf", HM_PRIO_TEE_AGENT, true },
#elif TEE_SUPPORT_HUK_SERVICE_32BIT
    { TEE_SERVICE_HUK, HUK_TASK_NAME, "/huk_service.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef TEE_SUPPORT_TCMGR_SERVICE_64BIT
    { TEE_SERVICE_TCMGR, TCMGR_SERVICE_TASK_NAME, "/tcmgr_service.elf", HM_PRIO_TEE_AGENT, true },
#elif TEE_SUPPORT_TCMGR_SERVICE_32BIT
    { TEE_SERVICE_TCMGR, TCMGR_SERVICE_TASK_NAME, "/tcmgr_service.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef TEE_SUPPORT_PERM_64BIT
    {TEE_SERVICE_PERM, PERM_SERVICE_NAME, "/permission_service.elf", HM_PRIO_TEE_AGENT, true},
#elif TEE_SUPPORT_PERM_32BIT
    {TEE_SERVICE_PERM, PERM_SERVICE_NAME, "/permission_service.elf", HM_PRIO_TEE_AGENT, false},
#endif
};

static const uint32_t g_teeos_builtin_task_num =
    sizeof(g_teeos_builtin_task_infos) / sizeof(g_teeos_builtin_task_infos[0]);

uint32_t get_teeos_builtin_task_nums(void)
{
    return g_teeos_builtin_task_num;
}

const struct task_info_st *get_teeos_builtin_task_infos(void)
{
    return g_teeos_builtin_task_infos;
}

#define SSA_SHRINK_STACK_DIV  4
#define SSA_DEFAULT_STACK_MUL 8
#define SSA_DEFAULT_HEAP_MUL  8
#define RPMB_DEFAULT_HEAP_MUL 8
#define RPMB_HUK_STACK_DIV    4
#define RPMB_HUK_HEAP_DIV     2
#define SSA_DEFAULT_HEAP_HEAPMGR_MUL  24
#define HUK_DEFAULT_HEAP_HEAPMGR_MUL  24
#define TCMGR_DEFAULT_HEAP_HEAPMGR_MUL  24
#define PERM_SRV_STACK_SIZE (DEFAULT_STACK_SIZE * 8)
#define PERM_SRV_HEAP_SIZE  (DEFAULT_HEAP_SIZE * 3)
#define PERM_SRV_DEFAULT_HEAP_HEAPMGR_MUL  (DEFAULT_HEAP_SIZE * 24)

/* build in service propertys for teeos */
const struct ta_property g_teeos_service_property[] = {
    /* uuid  stack  heap  instance multi_session  alive ssa_enum_enable other_property other_property_len */
    { TEE_SERVICE_REET, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
#if (defined TEE_SUPPORT_SSA_64BIT || defined TEE_SUPPORT_SSA_32BIT)
#ifdef SSA_SHRINK_MEMORY
    { TEE_SERVICE_SSA, DEFAULT_STACK_SIZE / SSA_SHRINK_STACK_DIV, DEFAULT_HEAP_SIZE,
      true, false, false, false, NULL, 0 },
#else
#ifdef CONFIG_MALLOC_HEAPMGR
    { TEE_SERVICE_SSA, DEFAULT_STACK_SIZE * SSA_DEFAULT_STACK_MUL, DEFAULT_HEAP_SIZE * SSA_DEFAULT_HEAP_HEAPMGR_MUL,
      true, false, false, false, NULL, 0 },
#else
    { TEE_SERVICE_SSA, DEFAULT_STACK_SIZE * SSA_DEFAULT_STACK_MUL, DEFAULT_HEAP_SIZE * SSA_DEFAULT_HEAP_MUL,
      true, false, false, false, NULL, 0 },
#endif
#endif
#endif
#if (defined TEE_SUPPORT_HUK_SERVICE_32BIT || defined TEE_SUPPORT_HUK_SERVICE_64BIT)
#ifdef CONFIG_MALLOC_HEAPMGR
    { TEE_SERVICE_HUK, DEFAULT_STACK_SIZE / RPMB_HUK_STACK_DIV, DEFAULT_HEAP_SIZE * HUK_DEFAULT_HEAP_HEAPMGR_MUL,
      true, false, false, false, NULL, 0 },
#else
    { TEE_SERVICE_HUK, DEFAULT_STACK_SIZE / RPMB_HUK_STACK_DIV, DEFAULT_HEAP_SIZE / RPMB_HUK_HEAP_DIV,
      true, false, false, false, NULL, 0 },
#endif
#endif
#if (defined TEE_SUPPORT_TCMGR_SERVICE_64BIT || defined TEE_SUPPORT_TCMGR_SERVICE_32BIT)
    { TEE_SERVICE_TCMGR, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE * TCMGR_DEFAULT_HEAP_HEAPMGR_MUL,
      true, false, false, false, NULL, 0 },
#endif
#if (defined TEE_SUPPORT_PERM_64BIT || defined TEE_SUPPORT_PERM_32BIT)
#ifdef CONFIG_MALLOC_HEAPMGR
    { TEE_SERVICE_PERM, PERM_SRV_STACK_SIZE, PERM_SRV_DEFAULT_HEAP_HEAPMGR_MUL, true, false, false, false, NULL, 0 },
#else
    { TEE_SERVICE_PERM, PERM_SRV_STACK_SIZE, PERM_SRV_HEAP_SIZE, true, false, false, false, NULL, 0 },
#endif
#endif
};

static const uint32_t g_teeos_service_property_num =
    sizeof(g_teeos_service_property) / sizeof(g_teeos_service_property[0]);

uint32_t get_teeos_service_property_num(void)
{
    return g_teeos_service_property_num;
}

const struct ta_property *get_teeos_service_property_config(void)
{
    return g_teeos_service_property;
}


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
