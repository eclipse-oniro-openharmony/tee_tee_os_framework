/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: product configs
 * Create: 2020-03-10
 */

#include "tee_config.h"
#include <sys/hm_priorities.h> /* for `HM_PRIO_TEE_*` */
#include "product_uuid.h"
#include "product_uuid_public.h"
#include "task_name.h"
#include "tee_reserve.h"
#include "sre_access_control.h"

/* should be kept consistent with DTS */
const struct rsv_mem_pool_uuid_item g_rsv_mem_pool_configs[] = {
};

const uint32_t g_rsv_mem_pool_num = sizeof(g_rsv_mem_pool_configs) / sizeof(g_rsv_mem_pool_configs[0]);

#ifdef CONFIG_AUTH_ENHANCE
struct call_info g_kernel_ca_whitelist[] = {
    { "antiroot-ca", true, 0, INVALID_PID, TEE_SERVICE_ANTIROOT },
    { "sec_boot", true, 0, INVALID_PID, TEE_SERVICE_SECBOOT },
    { "sec_mem", false, 0, INVALID_PID, TEE_SERVICE_SECMEM },
    { "ufs_key_restore", true, 0, INVALID_PID, TEE_SERVICE_FILE_ENCRY },
    { "/vendor/bin/hw/android.hardware.media.omx@1.0-service", true, 0, INVALID_PID, TEE_SERVICE_HIVCODEC },
    { "/dev/bdkernel_ca", true, 0, INVALID_PID, TEE_SERVICE_BDKERNEL },
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
#ifdef TEE_SUPPORT_ANTIROOT
    {TEE_SERVICE_ANTIROOT, ANTIROOT_TASK_NAME,  "/antiroot.elf",    HM_PRIO_TEE_TA, false},
#endif
#ifdef TEE_SUPPORT_GATEKEEPER_64BIT
    {TEE_SERVICE_GATEKEEPER, GATEKEEPER_TASK_NAME,  "/gatekeeper.elf",  HM_PRIO_TEE_TA, true},
#elif TEE_SUPPORT_GATEKEEPER_32BIT
    {TEE_SERVICE_GATEKEEPER, GATEKEEPER_TASK_NAME,  "/gatekeeper.elf",  HM_PRIO_TEE_TA, false},
#endif
#ifdef TEE_SUPPORT_ATTESTATION_TA
    {TEE_SERVICE_ATTESTATION_TA, ATTESTATION_TA_TASK_NAME,  "/attestation_ta.elf",  HM_PRIO_TEE_TA, false},
#endif
    {TEE_SERVICE_KDS, KDS_TASK_NAME,        "/kds.elf",     HM_PRIO_TEE_TA, false},
    {TEE_SERVICE_BDKERNEL, BDKERNEL_TASK_NAME,  "/bdkernel.elf",    HM_PRIO_TEE_TA, false},
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
    {TEE_SERVICE_SECBOOT, SECBOOT_TASK_NAME,    "/secboot.elf",     HM_PRIO_TEE_TA, false},
    {TEE_SERVICE_STORAGE, STORAGE_TASK_NAME,    "/storage.elf",     HM_PRIO_TEE_TA, false},
#ifdef TEE_SUPPORT_SEM
    {TEE_SERVICE_SEM, SEM_TASK_NAME,        "/sem.elf",     HM_PRIO_TEE_TA, false},
#endif
    {TEE_SERVICE_HIVCODEC, HIVCODEC_TASK_NAME, "/hivcodec.elf",   HM_PRIO_TEE_TA, false},
    {TEE_SERVICE_SECMEM, SECMEM_TASK_NAME,      "/secmem.elf", HM_PRIO_TEE_TA, false},
    {TEE_SERVICE_FILE_ENCRY, FILE_ENCRY_TASK_NAME,      "/file_encry.elf", HM_PRIO_TEE_TA, false},
#ifdef TEE_SUPPORT_TUI_64BIT
    {TEE_SERVICE_TUI, TUI_TASK_NAME,     "/tui.elf", HM_PRIO_TEE_TA, true},
#endif
#ifdef TEE_SUPPORT_TUI_32BIT
    {TEE_SERVICE_TUI, TUI_TASK_NAME,     "/tui.elf", HM_PRIO_TEE_TA, false},
#endif
#if (defined CONFIG_HISI_SECFLASH) || (defined HISI_MSP_SECFLASH)
    { TEE_SERVICE_SEC_FLASH, SEC_FLASH_TASK_NAME, "/sec_flash.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef TEE_SUPPORT_SE_SERVICE_64BIT
    { TEE_SERVICE_SE, SE_TASK_NAME, "/se_service.elf", HM_PRIO_TEE_AGENT, true },
#elif TEE_SUPPORT_SE_SERVICE_32BIT
    { TEE_SERVICE_SE, SE_TASK_NAME, "/se_service.elf", HM_PRIO_TEE_AGENT, false },
#endif
    {TEE_SERVICE_BIO, BIO_TASK_NAME,     "/biometric.elf", HM_PRIO_TEE_AGENT, false},
#ifdef TEE_SUPPORT_SECISP
    {TEE_SERVICE_SECISP, SECISP_TASK_NAME,      "/secisp.elf", HM_PRIO_TEE_TA, false},
#endif
#ifdef CONFIG_GENERIC_ROT
    { TEE_SERVICE_ROT, ROT_TASK_NAME, "/rot.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef CONFIG_GENERIC_ART
    { TEE_SERVICE_ART, ART_TASK_NAME, "/art.elf", HM_PRIO_TEE_AGENT, false },
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
    { TEE_SERVICE_CRYPT, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
    { TEE_SERVICE_EFUSE, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
    { TEE_SERVICE_HDCP, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#if (defined TEE_SUPPORT_KEYMASTER_32BIT || defined TEE_SUPPORT_KEYMASTER_64BIT)
#define STACK_KEYMASTER 8
#define HEAP_KEYMASTER  13
    { TEE_SERVICE_KEYMASTER, DEFAULT_STACK_SIZE * STACK_KEYMASTER, DEFAULT_HEAP_SIZE * HEAP_KEYMASTER,
      true, true, false, false, "gpd.ta.api_level:3", 19 },
#endif
#if (defined TEE_SUPPORT_GATEKEEPER_32BIT || defined TEE_SUPPORT_GATEKEEPER_64BIT)
    { TEE_SERVICE_GATEKEEPER, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#endif
#ifdef TEE_SUPPORT_ATTESTATION_TA
    { TEE_SERVICE_ATTESTATION_TA, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true,     true,   false,  false, NULL, 0 },
#endif
    { TEE_SERVICE_SECBOOT, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, true, false, NULL, 0 },
    { TEE_SERVICE_VDEC, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
#ifdef TEE_SUPPORT_ANTIROOT
    { TEE_SERVICE_ANTIROOT, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#endif
#ifdef TEE_SUPPORT_SEM
    { TEE_SERVICE_SEM, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#endif
#define STACK_PERM 8
#define HEAP_PERM 3
    { TEE_SERVICE_PERM, DEFAULT_STACK_SIZE * STACK_PERM, DEFAULT_HEAP_SIZE * HEAP_PERM,
      true, false, false, false, NULL, 0 },
    { TEE_SERVICE_KDS, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
    { TEE_SERVICE_BDKERNEL, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#if (defined TEE_SUPPORT_TUI_32BIT || defined TEE_SUPPORT_TUI_64BIT)
#define STACK_TUI 8
#define HEAP_TUI 16
    { TEE_SERVICE_TUI, DEFAULT_STACK_SIZE * STACK_TUI, DEFAULT_HEAP_SIZE * HEAP_TUI,
      true, false, false, false, NULL, 0 },
#endif
#if (defined TEE_SUPPORT_SE_SERVICE_32BIT || defined TEE_SUPPORT_SE_SERVICE_64BIT)
    { TEE_SERVICE_SE, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
#endif
#if (defined CONFIG_HISI_SECFLASH) || (defined HISI_MSP_SECFLASH)
    { TEE_SERVICE_SEC_FLASH, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
#endif
    {TEE_SERVICE_BIO, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true,  false,   false, false, NULL, 0},
#ifdef TEE_SUPPORT_HIVCODEC
    { TEE_SERVICE_HIVCODEC, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, false, true, false, false, NULL, 0 },
#endif

#ifdef TEE_SUPPORT_TZMP2
    { TEE_SERVICE_SECMEM, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#endif
#ifdef TEE_SUPPORT_FILE_ENCRY
#ifdef TEE_SUPPORT_FILE_ENCRY_V3
#define STACK_FILE_ENCRY_V3 2
#define HEAP_FILE_ENCRY_V3  4
    { TEE_SERVICE_FILE_ENCRY, DEFAULT_STACK_SIZE * STACK_FILE_ENCRY_V3, DEFAULT_HEAP_SIZE * HEAP_FILE_ENCRY_V3,
      true, false,  true, false, NULL, 0 },
#else
    { TEE_SERVICE_FILE_ENCRY, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true,  false, false, NULL, 0 },
#endif
#endif
#ifdef TEE_SUPPORT_SECISP
    { TEE_SERVICE_SECISP, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, true, false, NULL, 0 },
#endif
#ifdef CONFIG_GENERIC_ROT
    { TEE_SERVICE_ROT, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
#endif
#ifdef CONFIG_GENERIC_ART
    { TEE_SERVICE_ART, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
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
    { TEE_SERVICE_CRYPT, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_EFUSE, 0, EFUSE_GROUP_PERMISSION },
    { TEE_SERVICE_KEYMASTER, 0, CC_POWEROPER_GROUP_PERMISSION | KEY_FACTOR_GROUP_PERMISSION },
    { TEE_SERVICE_GATEKEEPER, 0, GATEKEEPER_GROUP_PERMISSION | CC_POWEROPER_GROUP_PERMISSION |
        KEY_FACTOR_GROUP_PERMISSION | SE_GROUP_PERMISSION },
    { TEE_SERVICE_SECBOOT, 0, SECBOOT_GROUP_PERMISSION | MDMCALL_GROUP_PERMISSION | CC_POWEROPER_GROUP_PERMISSION },
#ifdef TEE_SUPPORT_ATTESTATION_TA
    { TEE_SERVICE_ATTESTATION_TA, 0, GENERAL_GROUP_PERMISSION },
#endif
    { TEE_SERVICE_VDEC, 0, VDEC_GROUP_PERMISSION },
    { TEE_CHINADRM_2, 0, VDEC_GROUP_PERMISSION | GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_MULTIDRM, 0, VDEC_GROUP_PERMISSION | MSPE_VIDEO_GROUP_PERMISSION },
    { TEE_SERVICE_ANTIROOT, 0, TIMER_GROUP_PERMISSION | ROOTSTATUS_GROUP_PERMISSION | CC_POWEROPER_GROUP_PERMISSION },
    { TEE_SERVICE_SEM, 0, SE_GROUP_PERMISSION | TIMER_GROUP_PERMISSION | GENERIC_SE_GROUP_PERMISSION },
    { TEE_SERVICE_PERM, 0, PERMSRV_GROUP_PERMISSION | OEM_KEY_GROUP_PERMISSION },
    { TEE_SERVICE_KDS, 0, GENERAL_GROUP_PERMISSION },
#if (defined TEE_SUPPORT_TUI_32BIT || defined TEE_SUPPORT_TUI_64BIT)
    { TEE_SERVICE_TUI, 0, TUI_GROUP_PERMISSION | HWIMSG_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#if (defined TEE_SUPPORT_SE_SERVICE_32BIT || defined TEE_SUPPORT_SE_SERVICE_64BIT)
    { TEE_SERVICE_SE, 0, SE_GROUP_PERMISSION | TIMER_GROUP_PERMISSION | SE_STATUS_GROUP_PERMISSION },
#endif
#ifdef CONFIG_HISI_SECFLASH /* PhoenixC20 */
    { TEE_SERVICE_SEC_FLASH, 0, (CC_POWEROPER_GROUP_PERMISSION | SE_GROUP_PERMISSION |
                                 SECFLASH_GROUP_PERMISSION | CC_KEY_GROUP_PERMISSION) },
#endif
#ifdef HISI_MSP_SECFLASH /* Baltimore */
    { TEE_SERVICE_SEC_FLASH, 0, SECFLASH_GROUP_PERMISSION | MSPC_GROUP_PERMISSION },
#endif
    {TEE_SERVICE_BIO, 0, BIOMETRIC_GROUP_PERMISSION},
#ifdef TEE_SUPPORT_HIVCODEC
    { TEE_SERVICE_HIVCODEC, 0, VDEC_GROUP_PERMISSION | CC_POWEROPER_GROUP_PERMISSION },
#endif
    { TEE_SERVICE_DPHDCP, 0, DPHDCP_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_WFD, 0, HDCP_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION },
    { TEE_SERVICE_CHINADRM, 0, VDEC_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION },
    { TEE_SERVICE_WEAVER,   0, MSPC_GROUP_PERMISSION | CC_POWEROPER_GROUP_PERMISSION },
    { TEE_REMOTE_PIN,       0, MSPC_GROUP_PERMISSION },
#ifdef DEF_ENG
    { TEE_COMMON_TEST_TA1, 0, MSPC_GROUP_PERMISSION },
    { TEE_COMMON_TEST_TA2, 0, MSPC_GROUP_PERMISSION },
#endif
/* dymanic tasks */
    { TEE_SERVICE_U_TA_0, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_CCB, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_CFCA, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_BAK, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_FINGERPRINT, 0, FP_GROUP_PERMISSION | MSPC_GROUP_PERMISSION },
    { TEE_SERVICE_UDFINGERPRINT, 0, FP_GROUP_PERMISSION | MSPC_GROUP_PERMISSION },
    { TEE_FINGERPRINT_SENSOR_CHECK, 0, FP_GROUP_PERMISSION | MSPC_GROUP_PERMISSION },
    { TEE_FINGERPRINT_COATING_CHECK, 0, FP_GROUP_PERMISSION },
    { TEE_SERVICE_RPMBKEY, 0, GENERAL_GROUP_PERMISSION | MSPC_GROUP_PERMISSION },
    { TEE_SERVICE_SIGNTOOL, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_WALLET, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION | GENERIC_SE_GROUP_PERMISSION },
    { TEE_SERVICE_CRYPTOSMS, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_ALIPAY, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_WECHAT, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_SKYTONE, 0,
      TIMER_GROUP_PERMISSION | VSIM_GROUP_PERMISSION | HWIMSG_GROUP_PERMISSION | MDMCALL_GROUP_PERMISSION },
    { TEE_SERVICE_ANTITHEFT, 0, GENERAL_GROUP_PERMISSION | MSPC_GROUP_PERMISSION },
    { TEE_SERVICE_WIDEVINE_DRM, 0, VDEC_GROUP_PERMISSION | CC_POWEROPER_GROUP_PERMISSION },
    { TEE_SERVICE_IFAA, 0, HWIMSG_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_PLAYREADY_DRM, 0, GENERAL_GROUP_PERMISSION | VDEC_GROUP_PERMISSION },
    { TEE_SERVICE_DTV, 0, GENERAL_GROUP_PERMISSION },
    { TEE_DF_AC_SERVICE, 0, FR_GROUP_PERMISSION },
    { TEE_SERVICE_FACE_REC, 0, FR_GROUP_PERMISSION | MSPC_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION },
    { TEE_SERVICE_EID_U3, 0,
      SE_GROUP_PERMISSION | FR_GROUP_PERMISSION | TIMER_GROUP_PERMISSION |
          HWIMSG_GROUP_PERMISSION },
    { TEE_SERVICE_EID_U1, 0,
      SE_GROUP_PERMISSION | FR_GROUP_PERMISSION | TIMER_GROUP_PERMISSION |
          HWIMSG_GROUP_PERMISSION },
#ifdef FEATURE_IRIS
    { TEE_SERVICE_IRIS, 0, IRIS_GROUP_PERMISSION },
#endif
#ifdef TEE_SUPPORT_HIVCODEC
    { TEE_SERVICE_MMZ, 0, VDEC_GROUP_PERMISSION },
#endif
#ifdef TEE_SUPPORT_TZMP2
    { TEE_SERVICE_SECMEM, 0, SECMEM_GROUP_PERMISSION },
#endif

    { TEE_SERVICE_FINGERPRINT_SAVEIMAGE, 0, FP_GROUP_PERMISSION },
#ifdef TEE_SUPPORT_FILE_ENCRY
#ifdef TEE_SUPPORT_FILE_ENCRY_V3
    { TEE_SERVICE_FILE_ENCRY, 0, FILE_ENCRY_GROUP_PERMISSION | CC_CRYPTO_GROUP_PERMISSION |
      CC_POWEROPER_GROUP_PERMISSION | MSPC_GROUP_PERMISSION | CC_KEY_GROUP_PERMISSION },
#else
    { TEE_SERVICE_FILE_ENCRY, 0, FILE_ENCRY_GROUP_PERMISSION },
#endif
#endif
    { TEE_SERVICE_AI, 0, TIMER_GROUP_PERMISSION | AI_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION |
      DYNAMIC_ION_PERMISSION | NPU_GROUP_PERMISSION },
    { TEE_SERVICE_PANPAY, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_EIIUS, 0, SECBOOT_GROUP_PERMISSION  | CC_POWEROPER_GROUP_PERMISSION },
    { TEE_SERVICE_DRM_GRALLOC, 0, SECMEM_GROUP_PERMISSION },
    { TEE_SERVICE_EPS, 0, CRYPTO_ENHANCE_GROUP_PERMISSION | MSPC_GROUP_PERMISSION | MSPE_VIDEO_GROUP_PERMISSION },
#ifdef TEE_SUPPORT_SECISP
    { TEE_SERVICE_SECISP, 0, ISP_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION },
#endif
#ifdef CONFIG_GENERIC_ROT
    { TEE_SERVICE_ROT, 0, MSPC_GROUP_PERMISSION },
#endif
    { TEE_SERVICE_AI_TINY, 0, TIMER_GROUP_PERMISSION |
      AI_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION | DYNAMIC_ION_PERMISSION | NPU_GROUP_PERMISSION },
#ifdef CONFIG_GENERIC_ART
    { TEE_SERVICE_ART, 0, MSPC_GROUP_PERMISSION },
#endif
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
