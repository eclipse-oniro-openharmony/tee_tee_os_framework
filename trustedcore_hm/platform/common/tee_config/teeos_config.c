/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teeos platform configs
 * Create: 2020-03-20
 */
#include "tee_config.h"
#include <ac.h>
#include <security_ops.h>
#include <sys/hm_priorities.h> /* for HM_PRIO_TEE_* */
#include "product_uuid.h"
#include "product_uuid_public.h"
#include "sre_access_control.h"

#define WEAK __attribute__((weak))

#ifdef TEE_DISABLE_CA_SIGN
const int g_tee_disable_ca_auth = TEE_DISABLE_CA_SIGN;
#else
const int g_tee_disable_ca_auth;
#endif

int get_tee_disable_ca_auth(void)
{
    return g_tee_disable_ca_auth;
}

const uint32_t g_tee_audit_event_enabled =
    (ENABLE_TEE_AUDIT_EVENT_ONCE_REG_RDRMEM | ENABLE_TEE_AUDIT_EVENT_ONCE_REG_NTFMEM |
     ENABLE_TEE_AUDIT_EVENT_ONCE_REG_REGMAILBOX | ENABLE_TEE_AUDIT_EVENT_GT_EXCPTION);

uint32_t get_tee_audit_event_enabled(void)
{
    return g_tee_audit_event_enabled;
}

WEAK const struct drvlib_load_caller_info g_drvlib_load_caller_info[] = {
};

WEAK const uint32_t g_drvlib_load_caller_num = 0;

/* drv frame config info */
static struct drv_frame_info g_drv_frame_configs[] = {
#if defined(TEE_SUPPORT_PLATDRV_64BIT) || defined(TEE_SUPPORT_PLATDRV_32BIT)
    { "platdrv", AC_SID_PLATDRV, 0, TASKMAP2TASK_J, 0, 0, TEE_SERVICE_PLATDRV, true },
    { "multidrv", AC_SID_PLATDRV, 0, TASKMAP2TASK_J, 0, 0, TEE_SERVICE_PLATDRV, false },
#endif
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    { "tee_drv_server", AC_SID_TEE_DRV_SERVER, 0, TASKMAP2TASK_J, 0, 0, TEE_DRV_SERVER, true },
    { "tee_drv_server_multi", AC_SID_TEE_DRV_SERVER, 0, TASKMAP2TASK_J, 0, 0, TEE_DRV_SERVER, false },
#endif
};

const uint32_t g_drv_frame_num = sizeof(g_drv_frame_configs) / sizeof(g_drv_frame_configs[0]);

uint32_t get_drv_frame_nums(void)
{
    return g_drv_frame_num;
}

struct drv_frame_info *get_drv_frame_infos(void)
{
    return g_drv_frame_configs;
}

/*
 * die_size is dependent on platforms index defined in plat.mk
 * WITH_XXX_PLATFORM
 * when new platforms added here, the array should be modefied
 * THIS SEQUENCE SHOULD NOT BE MODEFIED
 */
static const uint32_t g_die_id_size[] = { OTHER_DIE_ID_SIZE,
                                          M_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE,
                                          OTHER_DIE_ID_SIZE };

static const uint32_t g_die_id_size_num = sizeof(g_die_id_size) / sizeof(g_die_id_size[0]);

uint32_t get_die_id_size_num(void)
{
    return g_die_id_size_num;
}

const uint32_t *get_tee_die_id_size(void)
{
    return g_die_id_size;
}

const struct task_info_st g_teeos_builtin_task_infos[] = {
#ifdef TEE_SUPPORT_RPMB_64BIT
    { TEE_SERVICE_RPMB, RPMB_TASK_NAME, "/rpmb.elf", HM_PRIO_TEE_AGENT, true },
#elif TEE_SUPPORT_RPMB_32BIT
    { TEE_SERVICE_RPMB, RPMB_TASK_NAME, "/rpmb.elf", HM_PRIO_TEE_AGENT, false },
#endif
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
#if (defined TEE_SUPPORT_RPMB_64BIT || defined TEE_SUPPORT_RPMB_32BIT)
    { TEE_SERVICE_RPMB, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE * RPMB_DEFAULT_HEAP_MUL,
      true, false, false, false, NULL, 0 },
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

const struct ta_permission g_teeos_ta_permission_config[] = {
    { TEE_SERVICE_REET, 0, SMC_GROUP_PERMISSION },
#if (defined TEE_SUPPORT_RPMB_64BIT || defined TEE_SUPPORT_RPMB_32BIT)
    { TEE_SERVICE_RPMB, 0,
      RPMB_GENERIC_PERMISSION | RPMB_SPECIFIC_PERMISSION | CC_POWEROPER_GROUP_PERMISSION },
#endif
#if (defined TEE_SUPPORT_HUK_SERVICE_32BIT || defined TEE_SUPPORT_HUK_SERVICE_64BIT)
    { TEE_SERVICE_HUK, 0, GENERAL_GROUP_PERMISSION | CC_KEY_GROUP_PERMISSION | OEM_KEY_GROUP_PERMISSION},
#endif
#ifdef DEF_ENG
    { TEE_SERVICE_ECHO, 0, ALL_GROUP_PERMISSION },
    { TEE_SERVICE_UT, 0, ALL_GROUP_PERMISSION },
    { TEE_SERVICE_KERNELMEMUSAGE, 0, ALL_GROUP_PERMISSION },
    { TEE_SERVICE_HELLOWORLD, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_TIMER_UT, 0, ALL_GROUP_PERMISSION },
    { TEE_SERVICE_TEST_API, 0, ALL_GROUP_PERMISSION },
    { TEE_SERVICE_PERMCTRL_UT, 0, GENERAL_GROUP_PERMISSION },
#endif
};

static const uint32_t g_teeos_ta_permission_num =
    sizeof(g_teeos_ta_permission_config) / sizeof(g_teeos_ta_permission_config[0]);

uint32_t get_teeos_ta_permission_num(void)
{
    return g_teeos_ta_permission_num;
}

const struct ta_permission *get_teeos_ta_permission_config(void)
{
    return g_teeos_ta_permission_config;
}

WEAK const struct ext_agent_uuid_item *get_ext_agent_whitelist(void)
{
    return NULL;
}

WEAK uint32_t get_ext_agent_item_num(void)
{
    return 0;
}

WEAK const struct dynamic_mem_uuid_item *get_dyn_mem_config(void)
{
    return NULL;
}

WEAK uint32_t get_dyn_mem_config_num(void)
{
    return 0;
}

WEAK uint32_t get_drvlib_load_caller_nums(void)
{
    return 0;
}

WEAK const struct drvlib_load_caller_info *get_drvlib_load_caller_infos(void)
{
    return NULL;
}
