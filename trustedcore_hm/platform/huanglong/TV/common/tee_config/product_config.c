/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: product configs
 * Create: 2020-03-10
 */

#include "product_config.h"
#include <sys/hm_priorities.h> /* for `HM_PRIO_TEE_*` */
#include "tee_config.h"
#include "product_uuid.h"
#include "product_uuid_public.h"
#include "product_agent.h"
#include "task_name.h"
#include "tee_reserve.h"
#include "sre_access_control.h"

static const struct dynamic_mem_uuid_item g_dynamic_mem_uuid_configs[] = {
#ifdef DEF_ENG
    { CONFIGID_UT, UT_MEM_LEN, TEE_SERVICE_UT, DDR_SEC_EID },
#endif
    { CONFIGID_NPU, NPU_MEM_LEN, TEE_SERVICE_NPU_DRV, DDR_SEC_EID },
};

const uint32_t g_dynion_ta_num = sizeof(g_dynamic_mem_uuid_configs) / sizeof(g_dynamic_mem_uuid_configs[0]);

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
    {TEE_SERVICE_KDS, KDS_TASK_NAME,        "/kds.elf",     HM_PRIO_TEE_TA, false},
#ifdef TEE_SUPPORT_KEYMASTER_64BIT
    {TEE_SERVICE_KEYMASTER_HISI, KEYMASTER_TASK_NAME,    "/keymaster.elf",   HM_PRIO_TEE_TA, false},
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
#if (defined CONFIG_HISI_SECFLASH) || (defined HISI_MSP_SECFLASH)
    { TEE_SERVICE_SEC_FLASH, SEC_FLASH_TASK_NAME, "/sec_flash.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef TEE_SUPPORT_SE_SERVICE_64BIT
    { TEE_SERVICE_SE, SE_TASK_NAME, "/se_service.elf", HM_PRIO_TEE_AGENT, true },
#elif TEE_SUPPORT_SE_SERVICE_32BIT
    { TEE_SERVICE_SE, SE_TASK_NAME, "/se_service.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef CFG_HI_TEE_DEMO_SUPPORT
    { TEE_SERVICE_DEMO, HISI_DEMO_TASK_NAME, "/task_hisi_demo.elf", HM_PRIO_TEE_TA, false },
#endif
    {TEE_SERVICE_BIO, BIO_TASK_NAME,     "/biometric.elf", HM_PRIO_TEE_AGENT, false},
#ifdef TEE_SUPPORT_SECISP
    {TEE_SERVICE_SECISP, SECISP_TASK_NAME,  "/secisp.elf", HM_PRIO_TEE_TA, false},
#endif
#ifdef CONFIG_GENERIC_ROT
    { TEE_SERVICE_ROT, ROT_TASK_NAME, "/rot.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef CFG_HI_TEE_SSM_SUPPORT
    { TEE_SERVICE_SSM, HISI_SSM_TASK_NAME, "/task_hisi_ssm.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_SSM_TEST_SUPPORT
    { TEE_SERVICE_SSM_TEST, HISI_SSM_TEST_TASK_NAME, "/task_hisi_ssm_test.elf", HM_PRIO_TEE_TA, false },
    { TEE_SERVICE_SSM_TEST_2, HISI_SSM_TEST_2_TASK_NAME, "/task_hisi_ssm_test_2.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_DEMUX_SUPPORT
    { TEE_SERVICE_DMX, HISI_DMX_TASK_NAME, "/task_hisi_dmx.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_TEST_CIPHER_SUPPORT
    { TEE_SERVICE_TEST_CIPHER, HISI_TEST_CIPHER_TASK_NAME, "/task_hisi_test_cipher.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_KLAD_SUPPORT
    { TEE_SERVICE_KLAD, HISI_KLAD_TASK_NAME, "/task_hisi_klad.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_KEYSLOT_SUPPORT
    { TEE_SERVICE_KEYSLOT, HISI_KEYSLOT_TASK_NAME, "/task_hisi_keyslot.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_OTP_SUPPORT
    { TEE_SERVICE_OTP, HISI_OTP_TASK_NAME, "/task_hisi_otp.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_VFMW_SUPPORT
    { TEE_SERVICE_VFMW, HISI_VFMW_TASK_NAME, "/task_hisi_vfmw.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_SMMU_SUPPORT
    { TEE_SERVICE_SMMU, HISI_SMMU_TASK_NAME, "/smmu_task.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_COMMON_SUPPORT
    { TEE_SERVICE_COMMON, HISI_COMMON_TASK_NAME, "/task_hisi_common.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_PVR_SUPPORT
    { TEE_SERVICE_PVR, HISI_PVR_TASK_NAME, "/task_hisi_pvr.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_HDMITX_SUPPORT
    { TEE_SERVICE_HDMITX, HISI_HDMITX_TASK_NAME, "/task_hisi_hdmitx.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_HDMIRX_SUPPORT
    { TEE_SERVICE_HDMIRX, HISI_HDMIRX_TASK_NAME, "/task_hisi_hdmirx.elf", HM_PRIO_TEE_TA, false },
#endif
#ifdef CFG_HI_TEE_NPU_TEST_SUPPORT
    { TEE_SERVICE_NPU_TEST, HISI_NPU_TEST_TASK_NAME, "/task_hisi_npu_test.elf", HM_PRIO_TEE_TA, false },
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
    { TEE_SERVICE_KEYMASTER_HISI, DEFAULT_STACK_SIZE * STACK_KEYMASTER, DEFAULT_HEAP_SIZE * HEAP_KEYMASTER,
      true, true, false, false, "gpd.ta.api_level:3", 19 },
#endif
#if (defined TEE_SUPPORT_GATEKEEPER_32BIT || defined TEE_SUPPORT_GATEKEEPER_64BIT)
    { TEE_SERVICE_GATEKEEPER_HISI, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
#endif
#ifdef TEE_SUPPORT_ATTESTATION_TA
    { TEE_SERVICE_ATTESTATION_TA, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, false, false, NULL, 0 },
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
#ifdef TEE_SUPPORT_VLTMM_SRV
    { TEE_SERVICE_VLTMM_SRV, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
#endif
#ifdef TEE_SUPPORT_FILE_ENCRY
#ifdef TEE_SUPPORT_FILE_ENCRY_V3
#define STACK_FILE_ENCRY_V3 2
#define HEAP_FILE_ENCRY_V3  4
    { TEE_SERVICE_FILE_ENCRY,  DEFAULT_STACK_SIZE * STACK_FILE_ENCRY_V3, DEFAULT_HEAP_SIZE * HEAP_FILE_ENCRY_V3,
      true, false,  true, false, NULL, 0 },
#else
    { TEE_SERVICE_FILE_ENCRY,  DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true,  false, false, NULL, 0 },
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
#ifdef CFG_HI_TEE_DEMO_SUPPORT
    { TEE_SERVICE_DEMO, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_SSM_SUPPORT
    { TEE_SERVICE_SSM, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_SSM_TEST_SUPPORT
    { TEE_SERVICE_SSM_TEST, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
    { TEE_SERVICE_SSM_TEST_2, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_DEMUX_SUPPORT
    { TEE_SERVICE_DMX, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_KLAD_SUPPORT
    { TEE_SERVICE_KLAD, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_KEYSLOT_SUPPORT
    { TEE_SERVICE_KEYSLOT, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_OTP_SUPPORT
    { TEE_SERVICE_OTP, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_TEST_CIPHER_SUPPORT
    { TEE_SERVICE_TEST_CIPHER, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_VFMW_SUPPORT
    { TEE_SERVICE_VFMW, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_SMMU_SUPPORT
    { TEE_SERVICE_SMMU, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, true, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_COMMON_SUPPORT
    { TEE_SERVICE_COMMON, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_PVR_SUPPORT
    { TEE_SERVICE_PVR, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_HDMITX_SUPPORT
    { TEE_SERVICE_HDMITX, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_HDMIRX_SUPPORT
    { TEE_SERVICE_HDMIRX, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
#endif
#ifdef CFG_HI_TEE_NPU_TEST_SUPPORT
    { TEE_SERVICE_NPU_TEST, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, true, false, NULL, 0 },
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
    { TEE_SERVICE_KEYMASTER_HISI, 0, CC_POWEROPER_GROUP_PERMISSION },
    { TEE_SERVICE_GATEKEEPER_HISI, 0, GATEKEEPER_GROUP_PERMISSION },
    { TEE_SERVICE_SECBOOT, 0, SECBOOT_GROUP_PERMISSION | MDMCALL_GROUP_PERMISSION | CC_POWEROPER_GROUP_PERMISSION },
#ifdef TEE_SUPPORT_ATTESTATION_TA
    { TEE_SERVICE_ATTESTATION_TA, 0, GENERAL_GROUP_PERMISSION },
#endif
    { TEE_SERVICE_VDEC, 0, VDEC_GROUP_PERMISSION },
    { TEE_CHINADRM_2, 0, VDEC_GROUP_PERMISSION | GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_MULTIDRM, 0, VDEC_GROUP_PERMISSION },
    { TEE_SERVICE_ANTIROOT, 0, TIMER_GROUP_PERMISSION | ROOTSTATUS_GROUP_PERMISSION | CC_POWEROPER_GROUP_PERMISSION },
    { TEE_SERVICE_SEM, 0, SE_GROUP_PERMISSION | TIMER_GROUP_PERMISSION | GENERIC_SE_GROUP_PERMISSION },
    { TEE_SERVICE_PERM, 0, PERMSRV_GROUP_PERMISSION | OEM_KEY_GROUP_PERMISSION },
    { TEE_SERVICE_KDS, 0, GENERAL_GROUP_PERMISSION },
    { TEE_SERVICE_IMAXCRYPTO, 0, CC_POWEROPER_GROUP_PERMISSION },
#if (defined TEE_SUPPORT_TUI_32BIT || defined TEE_SUPPORT_TUI_64BIT)
    { TEE_SERVICE_TUI, 0, TUI_GROUP_PERMISSION | HWIMSG_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#if (defined TEE_SUPPORT_SE_SERVICE_32BIT || defined TEE_SUPPORT_SE_SERVICE_64BIT)
    { TEE_SERVICE_SE, 0, SE_GROUP_PERMISSION | TIMER_GROUP_PERMISSION | SE_STATUS_GROUP_PERMISSION },
#endif
#ifdef CONFIG_HISI_SECFLASH
    { TEE_SERVICE_SEC_FLASH, 0,
	  CC_POWEROPER_GROUP_PERMISSION | SE_GROUP_PERMISSION | CC_KEY_GROUP_PERMISSION | SECFLASH_GROUP_PERMISSION },
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
    { TEE_SERVICE_WEAVER,   0, MSPC_GROUP_PERMISSION },
    { TEE_REMOTE_PIN,       0, MSPC_GROUP_PERMISSION },
#ifdef DEF_ENG
    { TEE_COMMON_TEST_TA1, 0, MSPC_GROUP_PERMISSION },
    { TEE_COMMON_TEST_TA2, 0, MSPC_GROUP_PERMISSION },
#endif
/* dymanic tasks */
    { TEE_SERVICE_CCB, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_CFCA, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_BAK, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_UDFINGERPRINT, 0, FP_GROUP_PERMISSION },
    { TEE_SERVICE_RPMBKEY, 0, GENERAL_GROUP_PERMISSION },
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
#ifdef CFG_HI_TEE_DEMO_SUPPORT
    { TEE_SERVICE_DEMO, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_SSM_SUPPORT
    { TEE_SERVICE_SSM, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_SSM_TEST_SUPPORT
    { TEE_SERVICE_SSM_TEST, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_SSM_TEST_2, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_DEMUX_SUPPORT
    { TEE_SERVICE_DMX, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_TEST_CIPHER_SUPPORT
    { TEE_SERVICE_TEST_CIPHER, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_KLAD_SUPPORT
    { TEE_SERVICE_KLAD, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_KEYSLOT_SUPPORT
    { TEE_SERVICE_KEYSLOT, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_OTP_SUPPORT
    { TEE_SERVICE_OTP, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_VFMW_SUPPORT
    { TEE_SERVICE_VFMW, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_SMMU_SUPPORT
    { TEE_SERVICE_SMMU, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_COMMON_SUPPORT
    { TEE_SERVICE_COMMON, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_PVR_SUPPORT
    { TEE_SERVICE_PVR, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_HDMITX_SUPPORT
    { TEE_SERVICE_HDMITX, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_HDMIRX_SUPPORT
    { TEE_SERVICE_HDMIRX, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_NPU_TEST_SUPPORT
    { TEE_SERVICE_NPU_TEST, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_EMPTYDRM_SUPPORT
    { TEE_SERVICE_EMPTYDRM, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_PLAYREADY_SUPPORT
    { TEE_SERVICE_PLAYREADY, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef CFG_HI_TEE_WIDEVINE_SUPPORT
    { TEE_SERVICE_WIDEVINE, 0, GENERAL_GROUP_PERMISSION | TIMER_GROUP_PERMISSION },
#endif
#ifdef FEATURE_IRIS
    { TEE_SERVICE_IRIS, 0, IRIS_GROUP_PERMISSION },
#endif
#ifdef TEE_SUPPORT_HIVCODEC
    { TEE_SERVICE_MMZ, 0, VDEC_GROUP_PERMISSION },
#endif
#ifdef TEE_SUPPORT_TZMP2
    { TEE_SERVICE_SECMEM, 0, SECMEM_GROUP_PERMISSION },
#ifdef TEE_SUPPORT_VLTMM_SRV
    { TEE_SERVICE_VLTMM_SRV, 0, SECMEM_GROUP_PERMISSION },
#endif
#endif

    { TEE_SERVICE_FINGERPRINT_SAVEIMAGE, 0, FP_GROUP_PERMISSION },
#ifdef TEE_SUPPORT_FILE_ENCRY
#ifdef TEE_SUPPORT_FILE_ENCRY_V3
    { TEE_SERVICE_FILE_ENCRY, 0,
      FILE_ENCRY_GROUP_PERMISSION | CC_CRYPTO_GROUP_PERMISSION | CC_POWEROPER_GROUP_PERMISSION |
      MSPC_GROUP_PERMISSION },
#else
    { TEE_SERVICE_FILE_ENCRY, 0, FILE_ENCRY_GROUP_PERMISSION },
#endif
#endif
    { TEE_SERVICE_AI, 0, TIMER_GROUP_PERMISSION | AI_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION |
      DYNAMIC_ION_PERMISSION | NPU_GROUP_PERMISSION },
    { TEE_SERVICE_PANPAY, 0, TIMER_GROUP_PERMISSION },
    { TEE_SERVICE_EIIUS, 0, SECBOOT_GROUP_PERMISSION  | CC_POWEROPER_GROUP_PERMISSION },
    { TEE_SERVICE_DRM_GRALLOC, 0, SECMEM_GROUP_PERMISSION },
    { TEE_SERVICE_EPS, 0, CRYPTO_ENHANCE_GROUP_PERMISSION | MSPC_GROUP_PERMISSION },
#ifdef TEE_SUPPORT_SECISP
    { TEE_SERVICE_SECISP, 0, ISP_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION },
#endif
    { TEE_SERVICE_KMS, 0, CC_POWEROPER_GROUP_PERMISSION },
#ifdef CONFIG_GENERIC_ROT
    { TEE_SERVICE_ROT, 0, MSPC_GROUP_PERMISSION },
#endif
    { TEE_SERVICE_AI_TINY, 0,
      TIMER_GROUP_PERMISSION | AI_GROUP_PERMISSION | SECMEM_GROUP_PERMISSION | DYNAMIC_ION_PERMISSION |
      NPU_GROUP_PERMISSION },
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

static const struct ext_agent_uuid_item g_ext_agent_whitelist[] = {
    { TEE_SERVICE_FACE_REC, TEE_FACE_AGENT_ID },
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
