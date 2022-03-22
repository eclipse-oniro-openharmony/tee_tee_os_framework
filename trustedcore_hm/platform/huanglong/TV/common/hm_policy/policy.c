/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: policy definitions
 * Create: 2017-03-10
 */

#include <hm_msg_type.h> /* for ARRAY_SIZE */
#include <api/tee_common.h>
#include <security_obj_def.h>
#include <security_cap_def.h>
#include <security_ops.h>
#include <tee_common.h> /* uuid */
#include <product_uuid.h> /* uuid */
#include "product_uuid_public.h"
#include <tee_reserve.h> /* uuid */
#include <tee_defines.h> /* TEE_UUID */
#include "ac_const.h"
#include "ac_internal_idx.h"
#ifdef DEF_ENG
#include "policy_test.h"
#endif
#include "ac_map.h"
#include "public_defines.h"
#include "teecall_policy.h"

/*
 * ATTENTION:
 *
 * Please keep subjects in order of SID!
 *
 * tips:
 * 1. The order of SIDs
 *   1.1 SIDs of native applications are smaller than SIDs of TA.
 *   1.2 Native SIDs can be found in ac_uid.h and TA SIDs can be found in ac_uuid.h.
 *   1.3 SIDs are ordered in each of ac_uid.h & ac_uuid.h
 * 2. Some native applications which could be loaded by taldr run with TA SIDs.
 *    Please use TA SIDs in policies for that.
 */
static const struct ac_static_object g_ac_obj_ta_add_tui          = { sizeof(char), 1, ".rtosck.tui" };
static const struct ac_static_object g_ac_obj_ta_add_permsrv_file = { sizeof(char), 1, ".rtosck.permsrv_save_file" };
AC_DEFINE_SUBJ_BEG(ta_add)
    { AC_SID_TEE_SERVICE_RPMB, 0, NULL },
    { AC_SID_TEE_SERVICE_TUI, 0, NULL }, { AC_SID_TEE_SERVICE_BAK, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_SEC_FLASH, 0, NULL },
    { AC_SID_TEE_SERVICE_PERM, 1, &g_ac_obj_ta_add_permsrv_file },
    { AC_SID_TEE_SERVICE_U_TA_24, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_30, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_8, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_23, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_EID_U3, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_20, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_CCB, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_5, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_19, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_4, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_14, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_28, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_6, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_2, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_3, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_EID_U1, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_0, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_11, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_SE, 0, NULL },
    { AC_SID_TEE_SERVICE_IFAA, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_SSA, 0, NULL }, { AC_SID_TEE_SERVICE_HUK, 0, NULL },
    { AC_SID_TEE_SERVICE_U_TA_7, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_ROT, 0, NULL },
    { AC_SID_TEE_SERVICE_U_TA_21, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_22, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_1, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_9, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_26, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_12, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_BIO, 0, NULL },
    { AC_SID_TEE_SERVICE_U_TA_17, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_13, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_VLTMM_SRV, 0, NULL },
    { AC_SID_TEE_SERVICE_U_TA_18, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_THPTUI, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_ART, 0, NULL },
    { AC_SID_TEE_SERVICE_U_TA_10, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_U_TA_27, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_16, 1, &g_ac_obj_ta_add_tui }, { AC_SID_TEE_SERVICE_CFCA, 1, &g_ac_obj_ta_add_tui },
    { AC_SID_TEE_SERVICE_U_TA_29, 1, &g_ac_obj_ta_add_tui },
AC_DEFINE_SUBJ_END(ta_add)

static const taskmap2task_ac_req_t g_taskmap2task_service_vltmm_objs[] = {
    { AC_SID_TEE_SERVICE_VLTMM_SRV, AC_SID_TEE_SERVICE_AI_TINY },
    { AC_SID_TEE_SERVICE_VLTMM_SRV, AC_SID_TEE_SERVICE_FACE_REC },
    { AC_SID_TEE_SERVICE_VLTMM_SRV, AC_SID_TEE_SERVICE_AI },
    { AC_SID_TEE_SERVICE_VLTMM_SRV, AC_SID_TEE_SERVICE_SECMEM },
};

static const struct ac_static_object g_taskmap2task_service_vltmm_acobjs = {
    sizeof(taskmap2task_ac_req_t), ARRAY_SIZE(g_taskmap2task_service_vltmm_objs), g_taskmap2task_service_vltmm_objs
};
static const taskmap2task_ac_req_t g_taskmap2task_platdrv_objs[] = {
    { AC_SID_ALL, AC_SID_PLATDRV },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_TUI },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_WIDEVINE_DRM },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_FACE_REC },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_IRIS },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_CHINADRM },
    { AC_SID_PLATDRV, AC_SID_TEE_CHINADRM_2 },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_VDEC },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_HIVCODEC },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_PLAYREADY_DRM },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_MMZ },
    { AC_SID_PLATDRV, AC_SID_TEE_WEAVER_TA },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_WFD },
#ifdef DEF_ENG
    { AC_SID_PLATDRV, AC_SID_SUPER }, /* for ut_task */
#else
    { AC_SID_ALL, AC_SID_PLATDRV }, /* place holder */
#endif
    {AC_SID_PLATDRV, AC_SID_TEE_SERVICE_MULTIDRM},
#ifdef CONFIG_FACEID_TOF_AE
    { AC_SID_PLATDRV, AC_SID_TEE_DF_AC_SERVICE },
#else
    { AC_SID_ALL, AC_SID_PLATDRV }, /* place holder */
#endif
#ifdef TEE_SUPPORT_EID_DYN_ION
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_EID_U3 },
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_EID_U1 },
#else
    { AC_SID_ALL, AC_SID_PLATDRV }, /* place holder */
    { AC_SID_ALL, AC_SID_PLATDRV }, /* place holder */
#endif
#ifdef TEE_SUPPORT_AI
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_AI },
#else
    { AC_SID_ALL, AC_SID_PLATDRV }, /* place holder */
#endif
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_AI_TINY },
#else
    { AC_SID_ALL, AC_SID_PLATDRV }, /* place holder */
#endif
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    { AC_SID_PLATDRV, AC_SID_TEE_SERVICE_SECISP },
#else
    { AC_SID_ALL, AC_SID_PLATDRV }, /* place holder */
#endif
};

static const struct ac_static_object g_taskmap2task_platdrv_acobjs = {
    sizeof(taskmap2task_ac_req_t), ARRAY_SIZE(g_taskmap2task_platdrv_objs), g_taskmap2task_platdrv_objs
};

static const taskmap2task_ac_req_t g_taskmap2task_ai_objs[] = {
    { AC_SID_TEE_SERVICE_FACE_REC, AC_SID_TEE_SERVICE_AI },
};

static const struct ac_static_object g_taskmap2task_ai_acobjs = {
    sizeof(taskmap2task_ac_req_t), ARRAY_SIZE(g_taskmap2task_ai_objs), g_taskmap2task_ai_objs
};

static const taskmap2task_ac_req_t g_taskmap2task_ai_tiny_objs[] = {
    { AC_SID_TEE_SERVICE_FACE_REC, AC_SID_TEE_SERVICE_AI_TINY },
};

static const struct ac_static_object g_taskmap2task_ai_tiny_acobjs = {
    sizeof(taskmap2task_ac_req_t), ARRAY_SIZE(g_taskmap2task_ai_tiny_objs), g_taskmap2task_ai_tiny_objs
};

AC_DEFINE_SUBJ_BEG(taskmap2task)
    { AC_SID_TEE_SERVICE_AI_TINY, ARRAY_SIZE(g_taskmap2task_ai_tiny_objs), &g_taskmap2task_ai_tiny_acobjs },
    { AC_SID_TEE_SERVICE_VLTMM_SRV, ARRAY_SIZE(g_taskmap2task_service_vltmm_objs),
    &g_taskmap2task_service_vltmm_acobjs },
    { AC_SID_TEE_SERVICE_AI, ARRAY_SIZE(g_taskmap2task_ai_objs), &g_taskmap2task_ai_acobjs },
AC_DEFINE_SUBJ_END(taskmap2task)

AC_DEFINE_SUBJ_BEG(taskmap2drv)
AC_DEFINE_SUBJ_END(taskmap2drv)

AC_DEFINE_SUBJ_BEG(spawn_uuid)
AC_DEFINE_SUBJ_END(spawn_uuid)

AC_DEFINE_SUBJ_BEG(spawn)
AC_DEFINE_SUBJ_END(spawn)

AC_DEFINE_SUBJ_BEG(pmeminfo)
AC_DEFINE_SUBJ_END(pmeminfo)

AC_DEFINE_SUBJ_BEG(meminfo)
AC_DEFINE_SUBJ_END(meminfo)

AC_DEFINE_SUBJ_BEG(setuid)
AC_DEFINE_SUBJ_END(setuid)

AC_DEFINE_SUBJ_BEG(proc_status)
AC_DEFINE_SUBJ_END(proc_status)

AC_DEFINE_SUBJ_BEG(virt2phys)
    { AC_SID_RPMB, 0, NULL },
    { AC_SID_TEE_SERVICE_RPMB, 0, NULL },
AC_DEFINE_SUBJ_END(virt2phys)

AC_DEFINE_SUBJ_BEG(dyn_plc)
    { AC_SID_TEE_SERVICE_PERM, 0, NULL },
AC_DEFINE_SUBJ_END(dyn_plc)

AC_DEFINE_SUBJ_BEG(get_uuid)
    { AC_SID_TEE_SERVICE_SEC_FLASH, 0, NULL },
    { AC_SID_TEE_SERVICE_PERM, 0, NULL },
    { AC_SID_TEE_SERVICE_SE, 0, NULL },
    { AC_SID_TEE_SERVICE_HUK, 0, NULL },
    { AC_SID_TEE_SERVICE_ROT, 0, NULL },
    { AC_SID_TEE_SERVICE_BIO, 0, NULL },
    { AC_SID_TEE_SERVICE_VLTMM_SRV, 0, NULL },
    { AC_SID_TEE_SERVICE_ART, 0, NULL },
    { AC_SID_TEE_SERVICE_RPMB, 0, NULL },
AC_DEFINE_SUBJ_END(get_uuid)

AC_DEFINE_SUBJ_BEG(fops)
AC_DEFINE_SUBJ_END(fops)

AC_DEFINE_SUBJ_BEG(xip_map)
AC_DEFINE_SUBJ_END(xip_map)

AC_DEFINE_SUBJ_BEG(add_free_mem)
AC_DEFINE_SUBJ_END(add_free_mem)

AC_DEFINE_SUBJ_BEG(adddynmemlist)
AC_DEFINE_SUBJ_END(adddynmemlist)

AC_DEFINE_SUBJ_BEG(del_dyn_mem_list)
AC_DEFINE_SUBJ_END(del_dyn_mem_list)

AC_DEFINE_SUBJ_BEG(setprocsize)
AC_DEFINE_SUBJ_END(setprocsize)

AC_DEFINE_SUBJ_BEG(mmap_scatter)
    { AC_SID_TEE_SERVICE_VLTMM_SRV, 0, NULL },
AC_DEFINE_SUBJ_END(mmap_scatter)

AC_DEFINE_SUBJ_BEG(io_map)
AC_DEFINE_SUBJ_END(io_map)

AC_DEFINE_SUBJ_BEG(irq_acquire)
AC_DEFINE_SUBJ_END(irq_acquire)

AC_DEFINE_SUBJ_BEG(sysctrl_tick)
AC_DEFINE_SUBJ_END(sysctrl_tick)

AC_DEFINE_SUBJ_BEG(sysctrl_local_irq)
AC_DEFINE_SUBJ_END(sysctrl_local_irq)

AC_DEFINE_SUBJ_BEG(teesmc_acquire)
AC_DEFINE_SUBJ_END(teesmc_acquire)

AC_DEFINE_SUBJ_BEG(pid2cref)
AC_DEFINE_SUBJ_END(pid2cref)

AC_DEFINE_SUBJ_BEG(dumpvregion)
AC_DEFINE_SUBJ_END(dumpvregion)

AC_DEFINE_SUBJ_BEG(map_secure)
AC_DEFINE_SUBJ_END(map_secure)

AC_DEFINE_SUBJ_BEG(map_nonsecure)
AC_DEFINE_SUBJ_END(map_nonsecure)

static const sid_t g_map2task_service_rpmb_objs[] = {
    AC_SID_TEE_SERVICE_RPMB,
};

static const struct ac_static_object g_map2task_service_rpmb_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_rpmb_objs), g_map2task_service_rpmb_objs
};

static const sid_t g_map2task_service_ssa_objs[] = {
    AC_SID_TEE_SERVICE_SSA,
};

static const struct ac_static_object g_map2task_service_ssa_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_ssa_objs), g_map2task_service_ssa_objs
};
static const sid_t g_map2task_service_sec_flash_objs[] = {
    AC_SID_TEE_SERVICE_SEC_FLASH,
};

static const struct ac_static_object g_map2task_service_sec_flash_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_sec_flash_objs), g_map2task_service_sec_flash_objs
};

static const sid_t g_map2task_service_permsrv_objs[] = {
    AC_SID_TEE_SERVICE_PERM,
};

static const struct ac_static_object g_map2task_service_permsrv_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_permsrv_objs), g_map2task_service_permsrv_objs
};

static const sid_t g_map2task_service_tui_objs[] = {
    AC_SID_TEE_SERVICE_TUI,
};

static const struct ac_static_object g_map2task_service_tui_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_tui_objs), g_map2task_service_tui_objs
};

static const sid_t g_map2task_service_sesrv_objs[] = {
    AC_SID_TEE_SERVICE_SE,
};

static const struct ac_static_object g_map2task_service_sesrv_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_sesrv_objs), g_map2task_service_sesrv_objs
};

static const sid_t g_map2task_service_huksrv_objs[] = {
    AC_SID_TEE_SERVICE_HUK,
};

static const struct ac_static_object g_map2task_service_huksrv_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_huksrv_objs), g_map2task_service_huksrv_objs
};

static const sid_t g_map2task_service_bio_objs[] = {
    AC_SID_TEE_SERVICE_BIO,
};

static const struct ac_static_object g_map2task_service_bio_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_bio_objs), g_map2task_service_bio_objs
};

static const sid_t g_map2task_service_rot_objs[] = {
    AC_SID_TEE_SERVICE_ROT,
};

static const struct ac_static_object g_map2task_service_rot_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_rot_objs), g_map2task_service_rot_objs
};

static const sid_t g_map2task_service_art_objs[] = {
    AC_SID_TEE_SERVICE_ART,
};

static const struct ac_static_object g_map2task_service_art_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_art_objs), g_map2task_service_art_objs
};

static const sid_t g_map2task_service_vltmm_objs[] = {
    AC_SID_TEE_SERVICE_VLTMM_SRV,
};

static const struct ac_static_object g_map2task_service_vltmm_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_vltmm_objs), g_map2task_service_vltmm_objs
};

static const sid_t g_map2task_platdrv_objs[] = {
    AC_SID_GTASK,
    AC_SID_TEE_SERVICE_U_TA_1,
    AC_SID_TEE_SERVICE_U_TA_2,
    AC_SID_TEE_SERVICE_U_TA_3,
    AC_SID_TEE_SERVICE_U_TA_4,
    AC_SID_TEE_SERVICE_U_TA_5,
    AC_SID_TEE_SERVICE_U_TA_6,
    AC_SID_TEE_SERVICE_U_TA_7,
    AC_SID_TEE_SERVICE_U_TA_8,
    AC_SID_TEE_SERVICE_U_TA_9,
    AC_SID_TEE_SERVICE_U_TA_10,
    AC_SID_TEE_SERVICE_U_TA_11,
    AC_SID_TEE_SERVICE_U_TA_12,
    AC_SID_TEE_SERVICE_U_TA_13,
    AC_SID_TEE_SERVICE_U_TA_14,
    AC_SID_TEE_SERVICE_TUI,
    AC_SID_TEE_SERVICE_U_TA_16,
    AC_SID_TEE_SERVICE_U_TA_17,
    AC_SID_TEE_SERVICE_U_TA_18,
    AC_SID_TEE_SERVICE_U_TA_19,
    AC_SID_TEE_SERVICE_U_TA_20,
    AC_SID_TEE_SERVICE_U_TA_21,
    AC_SID_TEE_SERVICE_U_TA_22,
    AC_SID_TEE_SERVICE_U_TA_23,
    AC_SID_TEE_SERVICE_U_TA_24,
    AC_SID_TEE_SERVICE_U_TA_25,
    AC_SID_TEE_SERVICE_U_TA_26,
    AC_SID_TEE_SERVICE_U_TA_27,
    AC_SID_TEE_SERVICE_U_TA_28,
    AC_SID_TEE_SERVICE_U_TA_29,
    AC_SID_TEE_SERVICE_U_TA_30,
    AC_SID_TEE_SERVICE_U_TA_0,
    AC_SID_TEE_SERVICE_CCB,
    AC_SID_TEE_SERVICE_CFCA,
    AC_SID_TEE_SERVICE_BAK,
    AC_SID_TEE_SERVICE_IFAA,
    AC_SID_TEE_SERVICE_THPTUI,
    AC_SID_TEE_SERVICE_SECBOOT,
#ifdef DEF_ENG
    AC_SID_TEE_SERVICE_ECHO,
    AC_SID_TEE_SERVICE_UT,
    AC_SID_TEE_SERVICE_KERNELMEMUSAGE,
    AC_SID_TEE_SERVICE_TEST_API,
#else
    AC_SID_PLATDRV,          /* place holder */
    AC_SID_PLATDRV,          /* place holder */
    AC_SID_PLATDRV,          /* place holder */
    AC_SID_PLATDRV,          /* place holder */
#endif
    AC_SID_TEE_SERVICE_SKYTONE,
#ifdef DEF_ENG
    AC_SID_SUPER, /* for ut_task */
#else
    AC_SID_PLATDRV,          /* place holder */
#endif
    AC_SID_PLATDRV,
    AC_SID_TEE_SERVICE_FACE_REC,
    AC_SID_TEE_SERVICE_VOICE_REC,
    AC_SID_TEE_DF_AC_SERVICE,
    AC_SID_TEE_CHINADRM_2,
    AC_SID_TEE_SERVICE_EID_U1,
    AC_SID_TEE_SERVICE_EID_U3,
    AC_SID_TEE_SERVICE_CHINADRM,
    AC_SID_TEE_SERVICE_EIIUS,
    AC_SID_TEE_SERVICE_WIDEVINE_DRM,
    AC_SID_TEE_SERVICE_TUI,
    AC_SID_TEE_SERVICE_FACE_REC,
    AC_SID_TEE_WEAVER_TA,
    AC_SID_TEE_SERVICE_MULTIDRM,
    AC_SID_TEE_SERVICE_PLAYREADY_DRM,
#ifdef TEE_SUPPORT_AI
    AC_SID_TEE_SERVICE_AI,
#else
    AC_SID_PLATDRV,          /* place holder */
#endif
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    AC_SID_TEE_SERVICE_AI_TINY,
    AC_SID_TEE_SERVICE_HIVCODEC,
#else
    AC_SID_PLATDRV,          /* place holder */
    AC_SID_PLATDRV,          /* place holder */
#endif
};

static const struct ac_static_object g_map2task_platdrv_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_platdrv_objs), g_map2task_platdrv_objs
};

static const sid_t g_map2task_gtask_objs[] = {
    AC_SID_ALL,
};

static const struct ac_static_object g_map2task_gtask_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_gtask_objs), g_map2task_gtask_objs
};

static const sid_t g_map2task_ai_objs[] = {
    AC_SID_TEE_SERVICE_AI,
};

static const sid_t g_map2task_ai_tiny_objs[] = {
    AC_SID_TEE_SERVICE_AI_TINY,
};

static const struct ac_static_object g_map2task_ai_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_ai_objs), g_map2task_ai_objs
};

static const struct ac_static_object g_map2task_ai_tiny_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_ai_tiny_objs), g_map2task_ai_tiny_objs
};

static const sid_t g_map2task_face_objs[] = {
    AC_SID_TEE_SERVICE_FACE_REC,
};

static const struct ac_static_object g_map2task_face_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_face_objs), g_map2task_face_objs
};

AC_DEFINE_SUBJ_BEG(map2task)
    { AC_SID_TEE_SERVICE_RPMB, ARRAY_SIZE(g_map2task_service_rpmb_objs), &g_map2task_service_rpmb_acobjs },
    { AC_SID_TEE_SERVICE_TUI, ARRAY_SIZE(g_map2task_service_tui_objs), &g_map2task_service_tui_acobjs },
    { AC_SID_TEE_SERVICE_SEC_FLASH, ARRAY_SIZE(g_map2task_service_sec_flash_objs),
      &g_map2task_service_sec_flash_acobjs },
    { AC_SID_TEE_SERVICE_PERM, ARRAY_SIZE(g_map2task_service_permsrv_objs), &g_map2task_service_permsrv_acobjs },
    { AC_SID_TEE_SERVICE_SE, ARRAY_SIZE(g_map2task_service_sesrv_objs), &g_map2task_service_sesrv_acobjs },
    { AC_SID_TEE_SERVICE_SSA, ARRAY_SIZE(g_map2task_service_ssa_objs), &g_map2task_service_ssa_acobjs },
    { AC_SID_TEE_SERVICE_HUK, ARRAY_SIZE(g_map2task_service_huksrv_objs), &g_map2task_service_huksrv_acobjs },
    { AC_SID_TEE_SERVICE_ROT, ARRAY_SIZE(g_map2task_service_rot_objs), &g_map2task_service_rot_acobjs },
    { AC_SID_TEE_SERVICE_AI_TINY, ARRAY_SIZE(g_map2task_ai_tiny_objs), &g_map2task_ai_tiny_acobjs },
    { AC_SID_TEE_SERVICE_BIO, ARRAY_SIZE(g_map2task_service_bio_objs), &g_map2task_service_bio_acobjs },
    { AC_SID_TEE_SERVICE_VLTMM_SRV, ARRAY_SIZE(g_map2task_service_vltmm_objs), &g_map2task_service_vltmm_acobjs },
    { AC_SID_TEE_SERVICE_FACE_REC, ARRAY_SIZE(g_map2task_face_objs), &g_map2task_face_acobjs },
    { AC_SID_TEE_SERVICE_ART, ARRAY_SIZE(g_map2task_service_art_objs), &g_map2task_service_art_acobjs },
    { AC_SID_TEE_SERVICE_AI, ARRAY_SIZE(g_map2task_ai_objs), &g_map2task_ai_acobjs },
AC_DEFINE_SUBJ_END(map2task)

AC_DEFINE_SUBJ_BEG(unmap2task)
    { AC_SID_TEE_SERVICE_RPMB, 0, NULL },
    { AC_SID_TEE_SERVICE_TUI, 0, NULL },
    { AC_SID_TEE_SERVICE_SEC_FLASH, 0, NULL },
    { AC_SID_TEE_SERVICE_PERM, 0, NULL },
    { AC_SID_TEE_SERVICE_SSA, 0, NULL },
    { AC_SID_TEE_SERVICE_HUK, 0, NULL },
    { AC_SID_TEE_SERVICE_AI_TINY, 0, NULL },
    { AC_SID_TEE_SERVICE_VLTMM_SRV, 0, NULL },
    { AC_SID_TEE_SERVICE_FACE_REC, 0, NULL },
    { AC_SID_TEE_SERVICE_AI, 0, NULL },
    { AC_SID_TEE_SERVICE_SECMEM, 0, NULL },
AC_DEFINE_SUBJ_END(unmap2task)

AC_DEFINE_SUBJ_BEG(push_rnd)
    { AC_SID_CRYPTOMGR, 0, NULL },
AC_DEFINE_SUBJ_END(push_rnd)

#ifndef UINT64MAX
#define UINT64MAX ((uint64_t)-1)
#endif
#define TEE_PHY_BASE    0x0
#define TEE_PHY_OFFSET_1  0x500000
#define TEE_PHY_OFFSET_2  0x600000
static const mmap_physical_t g_mmap_physical_cap[] = {
    { 0, UINT64MAX },
};
static const struct ac_static_object g_mmap_physical_obj_all = {
    sizeof(mmap_physical_t), ARRAY_SIZE(g_mmap_physical_cap), g_mmap_physical_cap
};

AC_DEFINE_SUBJ_BEG(mmap_physical)
AC_DEFINE_SUBJ_END(mmap_physical)

AC_DEFINE_SUBJ_BEG(channel_register)
AC_DEFINE_SUBJ_END(channel_register)

AC_DEFINE_SUBJ_BEG(channel_acquire)
AC_DEFINE_SUBJ_END(channel_acquire)

#include "public_subject.h"


const TEE_UUID g_svm_bind_talist[] = {
#ifdef TEE_SUPPORT_AI
    TEE_SERVICE_AI
#endif
};
const uint32_t g_svm_bind_talist_num = sizeof(g_svm_bind_talist) / sizeof(TEE_UUID);

bool ac_taskmap2task_valid_subj_sid_vendor(uint64_t sid)
{
    switch (sid) {
    case AC_SID_TEE_SERVICE_ROT:
    case AC_SID_TEE_SERVICE_BIO:
    case AC_SID_TEE_SERVICE_AI_TINY:
    case AC_SID_TEE_SERVICE_ART:
    case AC_SID_TEE_SERVICE_VLTMM_SRV:
        return true;
    default:
        return false;
    }
}

bool ac_map2task_valid_subj_sid_vendor(uint64_t sid)
{
    switch (sid) {
    case AC_SID_TEE_SERVICE_ROT:
    case AC_SID_TEE_SERVICE_BIO:
    case AC_SID_TEE_SERVICE_AI_TINY:
    case AC_SID_TEE_SERVICE_ART:
    case AC_SID_TEE_SERVICE_VLTMM_SRV:
        return true;
    default:
        return false;
    }
}
