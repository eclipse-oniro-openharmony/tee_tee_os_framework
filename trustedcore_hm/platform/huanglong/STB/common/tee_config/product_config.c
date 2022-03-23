/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: product configs
 * Create: 2020-03-10
 */

#include "product_config.h"
#include "tee_config.h"
#include <sys/hm_priorities.h> /* for `HM_PRIO_TEE_*` */
#include "tee_config.h"
#include "product_uuid.h"
#include "product_uuid_public.h"
#include "product_agent.h"
#include "task_name.h"
#ifdef RESERVE_TA_PERM
#include "tee_reserve.h"
#endif
#include "sre_access_control.h"

static const struct dynamic_mem_uuid_item g_dynamic_mem_uuid_configs[] = {
#ifdef DEF_ENG
    { CONFIGID_UT, UT_MEM_LEN, TEE_SERVICE_UT, DDR_SEC_EID },
#endif
};

static const uint32_t g_dynion_ta_num = sizeof(g_dynamic_mem_uuid_configs) / sizeof(g_dynamic_mem_uuid_configs[0]);

const struct dynamic_mem_uuid_item *get_dyn_mem_config(void)
{
    return g_dynamic_mem_uuid_configs;
}

uint32_t get_dyn_mem_config_num(void)
{
    return g_dynion_ta_num;
}

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
#ifdef TEE_SUPPORT_GATEKEEPER_64BIT
    {TEE_SERVICE_GATEKEEPER_HISI, GATEKEEPER_TASK_NAME,  "/gatekeeper.elf",  HM_PRIO_TEE_TA, true},
#elif TEE_SUPPORT_GATEKEEPER_32BIT
    {TEE_SERVICE_GATEKEEPER_HISI, GATEKEEPER_TASK_NAME,  "/gatekeeper.elf",  HM_PRIO_TEE_TA, false},
#endif
    {TEE_SERVICE_ATTESTATION_TA, ATTESTATION_TA_TASK_NAME,  "/attestation_ta.elf",  HM_PRIO_TEE_TA, false},
    {TEE_SERVICE_KDS, KDS_TASK_NAME,        "/kds.elf",     HM_PRIO_TEE_TA, false},
#ifdef TEE_SUPPORT_KEYMASTER_64BIT
    {TEE_SERVICE_KEYMASTER, KEYMASTER_TASK_NAME,    "/keymaster.elf",   HM_PRIO_TEE_TA, true},
#elif TEE_SUPPORT_KEYMASTER_32BIT
    {TEE_SERVICE_KEYMASTER, KEYMASTER_TASK_NAME,    "/keymaster.elf",   HM_PRIO_TEE_TA, false},
#endif
#ifdef TEE_SUPPORT_PERM_64BIT
    {TEE_SERVICE_PERM, PERM_SERVICE_NAME,      "/permission_service.elf", HM_PRIO_TEE_AGENT, true},
#elif TEE_SUPPORT_PERM_32BIT
    {TEE_SERVICE_PERM, PERM_SERVICE_NAME,      "/permission_service.elf", HM_PRIO_TEE_AGENT, false},
#endif
    {TEE_SERVICE_STORAGE, STORAGE_TASK_NAME,    "/storage.elf",     HM_PRIO_TEE_TA, false},
#ifdef TEE_SUPPORT_SEM
    {TEE_SERVICE_SEM, SEM_TASK_NAME,        "/sem.elf",     HM_PRIO_TEE_TA, false},
#endif
#ifdef TEE_SUPPORT_TUI_64BIT
    {TEE_SERVICE_TUI, TUI_TASK_NAME,     "/tui.elf", HM_PRIO_TEE_TA, true},
#endif
#ifdef TEE_SUPPORT_TUI_32BIT
    {TEE_SERVICE_TUI, TUI_TASK_NAME,     "/tui.elf", HM_PRIO_TEE_TA, false},
#endif
#ifdef TEE_SUPPORT_SEC_FLASH
    { TEE_SERVICE_SEC_FLASH, SEC_FLASH_TASK_NAME, "/sec_flash.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef TEE_SUPPORT_SE_SERVICE
    { TEE_SERVICE_SE, SE_TASK_NAME, "/se_service_a32.elf", HM_PRIO_TEE_AGENT, false },
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
const struct ta_property g_product_service_property[] = {
    /* uuid  stack  heap  instance multi_session alive ssa_enum_enable other_property other_property_len */
    { TEE_SERVICE_STORAGE, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
    { TEE_SERVICE_HDCP, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#if (defined TEE_SUPPORT_KEYMASTER_32BIT || defined TEE_SUPPORT_KEYMASTER_64BIT)
#define STACK_KEYMASTER 8
#define HEAP_KEYMASTER  13
    { TEE_SERVICE_KEYMASTER, DEFAULT_STACK_SIZE * STACK_KEYMASTER, DEFAULT_HEAP_SIZE * HEAP_KEYMASTER,
      true, true, false, false, "gpd.ta.api_level:3", 19 },
#endif
#if (defined TEE_SUPPORT_GATEKEEPER_32BIT || defined TEE_SUPPORT_GATEKEEPER_64BIT)
    { TEE_SERVICE_GATEKEEPER_HISI, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#endif
    { TEE_SERVICE_ATTESTATION_TA, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#ifdef TEE_SUPPORT_SEM
    { TEE_SERVICE_SEM, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#endif
#define STACK_PERM 8
#define HEAP_PERM 3
    { TEE_SERVICE_PERM, DEFAULT_STACK_SIZE * STACK_PERM, DEFAULT_HEAP_SIZE * HEAP_PERM,
      true, false, false, false, NULL, 0 },
    { TEE_SERVICE_KDS, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#if (defined TEE_SUPPORT_TUI_32BIT || defined TEE_SUPPORT_TUI_64BIT)
#define STACK_TUI 8
#define HEAP_TUI 16
    { TEE_SERVICE_TUI, DEFAULT_STACK_SIZE * STACK_TUI, DEFAULT_HEAP_SIZE * HEAP_TUI,
      true, false, false, false, NULL, 0 },
#endif
#ifdef TEE_SUPPORT_SE_SERVICE
    { TEE_SERVICE_SE, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
#endif
#ifdef TEE_SUPPORT_SEC_FLASH
    { TEE_SERVICE_SEC_FLASH, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
#endif

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
    { TEE_SERVICE_STORAGE, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_HDCP, 0, CC_OEM_KEY_GROUP_PERMISSION },
    { TEE_SERVICE_KEYMASTER, 0, CC_POWEROPER_GROUP_PERMISSION },
    { TEE_SERVICE_GATEKEEPER_HISI, 0, CC_POWEROPER_GROUP_PERMISSION | GATEKEEPER_GROUP_PERMISSION },
    { TEE_SERVICE_ATTESTATION_TA, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_SEM, 0, SE_GROUP_PERMISSION | TIMER_GROUP_PERMISSION | GENERIC_SE_GROUP_PERMISSION },
    { TEE_SERVICE_PERM, 0, PERMSRV_GROUP_PERMISSION | OEM_KEY_GROUP_PERMISSION },
    { TEE_SERVICE_KDS, 0, GENERAL_GROUP_PERMISSION },
#if (defined TEE_SUPPORT_TUI_32BIT || defined TEE_SUPPORT_TUI_64BIT)
    { TEE_SERVICE_TUI, 0, TUI_GROUP_PERMISSION | HWIMSG_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef TEE_SUPPORT_SE_SERVICE
    { TEE_SERVICE_SE, 0, SE_GROUP_PERMISSION | TIMER_GROUP_PERMISSION | SE_STATUS_GROUP_PERMISSION },
#endif
#ifdef TEE_SUPPORT_SEC_FLASH
    { TEE_SERVICE_SEC_FLASH, 0, (CC_POWEROPER_GROUP_PERMISSION | SE_GROUP_PERMISSION) },
#endif
    { TEE_SERVICE_DPHDCP, 0, DPHDCP_GROUP_PERMISSION },
    { TEE_SERVICE_CHINADRM, 0, VDEC_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION },
/* dymanic tasks */
    { TEE_SERVICE_CCB, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_CFCA, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_BAK, 0, TIMER_GROUP_PERMISSION },
#ifdef RESERVE_TA_PERM
    { TEE_SERVICE_U_TA_1, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_2, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_3, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_4, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_5, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_6, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_7, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_8, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_9, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_10, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_11, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_12, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_13, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_14, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_16, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_17, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_18, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_19, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_20, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_21, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_22, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_23, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_24, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_25, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_26, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_27, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_28, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_29, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_U_TA_30, 0, TIMER_GROUP_PERMISSION },
#endif
    { TEE_SERVICE_UDFINGERPRINT, 0, FP_GROUP_PERMISSION },
    { TEE_SERVICE_RPMBKEY, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_WALLET, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION | GENERIC_SE_GROUP_PERMISSION },
    { TEE_SERVICE_SKYTONE, 0,
      TIMER_GROUP_PERMISSION | VSIM_GROUP_PERMISSION | HWIMSG_GROUP_PERMISSION | MDMCALL_GROUP_PERMISSION },
    { TEE_SERVICE_ANTITHEFT, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_WIDEVINE_DRM, 0, VDEC_GROUP_PERMISSION },
    { TEE_SERVICE_IFAA, 0, HWIMSG_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_PLAYREADY_DRM, 0, GENERAL_GROUP_PERMISSION | VDEC_GROUP_PERMISSION },
    { TEE_SERVICE_FACE_REC, 0, FR_GROUP_PERMISSION },
    { TEE_SERVICE_EID_U3, 0,
      SE_GROUP_PERMISSION | FR_GROUP_PERMISSION | TIMER_GROUP_PERMISSION |
          HWIMSG_GROUP_PERMISSION },
    { TEE_SERVICE_EID_U1, 0,
      SE_GROUP_PERMISSION | FR_GROUP_PERMISSION | TIMER_GROUP_PERMISSION |
          HWIMSG_GROUP_PERMISSION },

#ifdef TEE_SUPPORT_FILE_ENCRY
    { TEE_SERVICE_FILE_ENCRY, 0, FILE_ENCRY_GROUP_PERMISSION },
#endif
    { TEE_SERVICE_AI, 0, TIMER_GROUP_PERMISSION | AI_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION |
      DYNAMIC_ION_PERMISSION | NPU_GROUP_PERMISSION },
    { TEE_SERVICE_PANPAY, 0, TIMER_GROUP_PERMISSION },
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

static const struct ext_agent_uuid_item g_ext_agent_whitelist[] = {
    { TEE_SERVICE_AI,     TEE_SECE_AGENT_ID },
#ifdef DEF_ENG
    { TEE_SERVICE_ECHO,     TEE_SECE_AGENT_ID },
#endif
};
static const uint32_t g_ext_agent_item_num = sizeof(g_ext_agent_whitelist) / sizeof(g_ext_agent_whitelist[0]);

const struct ext_agent_uuid_item *get_ext_agent_whitelist(void)
{
    return g_ext_agent_whitelist;
}

uint32_t get_ext_agent_item_num(void)
{
    return g_ext_agent_item_num;
}
