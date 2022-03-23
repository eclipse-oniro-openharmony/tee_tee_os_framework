/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: policy definitions
 * Author: l00422637
 * Create: 2017-03-10
 */

#include <hm_msg_type.h> /* for ARRAY_SIZE */
#include <api/tee_common.h>
#include <security_obj_def.h>
#include <security_cap_def.h>
#include <security_ops.h>
#include <tee_common.h> /* uuid */
#include <product_uuid.h> /* uuid */
#include "product_uuid_public.h" /* uuid */
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
static const struct ac_static_object g_ac_obj_ta_add_permsrv_file = { sizeof(char), 1, ".rtosck.permsrv_save_file" };
AC_DEFINE_SUBJ_BEG(ta_add)
    { AC_SID_TEE_SERVICE_SSA, 0, NULL },
    { AC_SID_TEE_SERVICE_HUK, 0, NULL },
    { AC_SID_TEE_SERVICE_PERM, 1, &g_ac_obj_ta_add_permsrv_file },
AC_DEFINE_SUBJ_END(ta_add)

static const taskmap2task_ac_req_t g_taskmap2task_platdrv_objs[] = {
    { AC_SID_ALL, AC_SID_PLATDRV },
#ifdef DEF_ENG
    { AC_SID_PLATDRV, AC_SID_SUPER }, /* for ut_task */
#else
    { AC_SID_ALL, AC_SID_PLATDRV }, /* place holder */
#endif
};

static const struct ac_static_object g_taskmap2task_platdrv_acobjs = {
    sizeof(taskmap2task_ac_req_t), ARRAY_SIZE(g_taskmap2task_platdrv_objs), g_taskmap2task_platdrv_objs
};

AC_DEFINE_SUBJ_BEG(taskmap2task)
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
AC_DEFINE_SUBJ_END(virt2phys)

AC_DEFINE_SUBJ_BEG(dyn_plc)
AC_DEFINE_SUBJ_END(dyn_plc)

AC_DEFINE_SUBJ_BEG(get_uuid)
    { AC_SID_TEE_SERVICE_PERM, 0, NULL },
    { AC_SID_TEE_SERVICE_HUK, 0, NULL },
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
#ifdef CONFIG_SMCMGR_EMBEDDED
{ AC_SID_GTASK, 0, NULL }
#endif
AC_DEFINE_SUBJ_END(teesmc_acquire)

AC_DEFINE_SUBJ_BEG(pid2cref)
AC_DEFINE_SUBJ_END(pid2cref)

AC_DEFINE_SUBJ_BEG(dumpvregion)
{ AC_SID_GTASK, 0, NULL },
AC_DEFINE_SUBJ_END(dumpvregion)

static const sid_t g_map2task_service_ssa_objs[] = {
    AC_SID_TEE_SERVICE_SSA,
};

static const struct ac_static_object g_map2task_service_ssa_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_ssa_objs), g_map2task_service_ssa_objs
};

static const sid_t g_map2task_platdrv_objs[] = {
    AC_SID_GTASK,
    AC_SID_PLATDRV,
#ifdef DEF_ENG
    AC_SID_TEE_SERVICE_ECHO,
    AC_SID_TEE_SERVICE_UT,
    AC_SID_TEE_SERVICE_KERNELMEMUSAGE,
    AC_SID_TEE_SERVICE_TEST_API,
    AC_SID_SUPER, /* for ut_task */
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


static const sid_t g_map2task_service_huksrv_objs[] = {
    AC_SID_TEE_SERVICE_HUK,
};

static const struct ac_static_object g_map2task_service_huksrv_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_service_huksrv_objs), g_map2task_service_huksrv_objs
};

#ifdef DEF_ENG
static const sid_t g_map2task_echo_objs[] = {
    AC_SID_TEE_SERVICE_ECHO,
};

static const struct ac_static_object g_map2task_echo_acobjs = {
    sizeof(sid_t), ARRAY_SIZE(g_map2task_echo_objs), g_map2task_echo_objs
};
#endif

AC_DEFINE_SUBJ_BEG(map2task)
#ifdef DEF_ENG
    { AC_SID_TEE_SERVICE_ECHO, ARRAY_SIZE(g_map2task_echo_objs), &g_map2task_echo_acobjs },
#endif
    { AC_SID_TEE_SERVICE_SSA, ARRAY_SIZE(g_map2task_service_ssa_objs), &g_map2task_service_ssa_acobjs },
    { AC_SID_TEE_SERVICE_HUK, ARRAY_SIZE(g_map2task_service_huksrv_objs), &g_map2task_service_huksrv_acobjs },
AC_DEFINE_SUBJ_END(map2task)

AC_DEFINE_SUBJ_BEG(unmap2task)
#ifdef DEF_ENG
    { AC_SID_TEE_SERVICE_ECHO, 0, NULL },
#endif
    { AC_SID_TEE_SERVICE_SSA, 0, NULL },
    { AC_SID_TEE_SERVICE_HUK, 0, NULL },
    { AC_SID_TEE_SERVICE_PERM, 0, NULL },
AC_DEFINE_SUBJ_END(unmap2task)

AC_DEFINE_SUBJ_BEG(push_rnd)
    { AC_SID_CRYPTOMGR, 0, NULL },
AC_DEFINE_SUBJ_END(push_rnd)

AC_DEFINE_SUBJ_BEG(map_secure)
AC_DEFINE_SUBJ_END(map_secure)

AC_DEFINE_SUBJ_BEG(map_nonsecure)
AC_DEFINE_SUBJ_END(map_nonsecure)

#ifndef UINT64MAX
#define UINT64MAX ((uint64_t)-1)
#endif

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

};
const uint32_t g_svm_bind_talist_num = sizeof(g_svm_bind_talist) / sizeof(TEE_UUID);
