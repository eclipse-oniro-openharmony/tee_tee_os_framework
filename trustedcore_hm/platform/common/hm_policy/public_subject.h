/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: policy public defines.
 * Create: 2020-10
 */

#ifndef PUBLIC_SUBJECT_H
#define PUBLIC_SUBJECT_H

/* public subject */
AC_DEFINE_SUBJ_BEG(pub_ta_add)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_TEESMCMGR, 0, NULL },
    { AC_SID_TALDR, 0, NULL },
    { AC_SID_GTASK, 0, NULL },
    { AC_SID_PLATDRV, 0, NULL },
    { AC_SID_DRV_TIMER, 0, NULL },
    { AC_SID_HMCCMGR, 0, NULL },
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    { AC_SID_TEE_DRV_SERVER, 0, NULL },
#endif
    T_POLICY(ta_add)
AC_DEFINE_SUBJ_END(pub_ta_add)

AC_DEFINE_SUBJ_BEG(pub_task_mapfile)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_FILEMGR, 0, NULL },
    T_POLICY(task_mapfile)
AC_DEFINE_SUBJ_END(pub_task_mapfile)

AC_DEFINE_SUBJ_BEG(task_mapfile)
AC_DEFINE_SUBJ_END(task_mapfile)

AC_DEFINE_SUBJ_BEG(pub_taskmap2task)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_PLATDRV, ARRAY_SIZE(g_taskmap2task_platdrv_objs), &g_taskmap2task_platdrv_acobjs },
    T_POLICY(taskmap2task)
AC_DEFINE_SUBJ_END(pub_taskmap2task)

AC_DEFINE_SUBJ_BEG(pub_taskmap2drv)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_PLATDRV, 0, NULL },
    { AC_SID_DRV_TIMER, 0, NULL },
    { AC_SID_HMCCMGR, 0, NULL },
    T_POLICY(taskmap2drv)
AC_DEFINE_SUBJ_END(pub_taskmap2drv)

AC_DEFINE_SUBJ_BEG(pub_spawn_uuid)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_GTASK, 0, NULL },
    T_POLICY(spawn_uuid)
AC_DEFINE_SUBJ_END(pub_spawn_uuid)

AC_DEFINE_SUBJ_BEG(pub_spawn)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_GTASK, 0, NULL },
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    { AC_SID_TEE_DRV_SERVER, 0, NULL },
#endif
    T_POLICY(spawn)
AC_DEFINE_SUBJ_END(pub_spawn)

AC_DEFINE_SUBJ_BEG(pub_pmeminfo)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    T_POLICY(pmeminfo)
AC_DEFINE_SUBJ_END(pub_pmeminfo)

AC_DEFINE_SUBJ_BEG(pub_meminfo)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_GTASK, 0, NULL },
    T_POLICY(meminfo)
AC_DEFINE_SUBJ_END(pub_meminfo)

AC_DEFINE_SUBJ_BEG(pub_setuid)
    { AC_SID_SUPER, 0, NULL },
    { AC_SID_TALDR, 0, NULL },
    T_POLICY(setuid)
AC_DEFINE_SUBJ_END(pub_setuid)

AC_DEFINE_SUBJ_BEG(pub_proc_status)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_PLATDRV, 0, NULL },
    { AC_SID_DRV_TIMER, 0, NULL },
    { AC_SID_FILEMGR, 0, NULL },
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    { AC_SID_TEE_DRV_SERVER, 0, NULL },
#endif
    T_POLICY(proc_status)
AC_DEFINE_SUBJ_END(pub_proc_status)

AC_DEFINE_SUBJ_BEG(pub_virt2phys)
    { AC_SID_PLATDRV, 0, NULL },
    /* for test */
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
    { AC_SID_TEE_SERVICE_UT, 0, NULL},
    { AC_SID_HM_TEEOS_TEST, 0, NULL},
#endif
AC_DEFINE_SUBJ_END(pub_virt2phys)

AC_DEFINE_SUBJ_BEG(pub_dyn_plc)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    { AC_SID_TEE_DRV_SERVER, 0, NULL },
#endif
    T_POLICY(dyn_plc)
AC_DEFINE_SUBJ_END(pub_dyn_plc)

AC_DEFINE_SUBJ_BEG(pub_get_uuid)
    { AC_SID_PLATDRV, 0, NULL },
    { AC_SID_DRV_TIMER, 0, NULL },
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    { AC_SID_TEE_DRV_SERVER, 0, NULL },
#endif
    { AC_SID_GTASK, 0, NULL },
AC_DEFINE_SUBJ_END(pub_get_uuid)

AC_DEFINE_SUBJ_BEG(pub_fops)
    { AC_SID_SUPER, 0, NULL },
    { AC_SID_TALDR, 0, NULL },
    { AC_SID_GTASK, 0, NULL },
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    { AC_SID_TEE_DRV_SERVER, 0, NULL },
#endif
#if defined(TEE_SUPPORT_PERM_64BIT) || defined(TEE_SUPPORT_PERM_32BIT)
    { AC_SID_TEE_SERVICE_PERM, 0, NULL },
#endif
    T_POLICY(fops)
AC_DEFINE_SUBJ_END(pub_fops)

AC_DEFINE_SUBJ_BEG(pub_xip_map)
    { AC_SID_SUPER, 0, NULL },
    T_POLICY(xip_map)
AC_DEFINE_SUBJ_END(pub_xip_map)

AC_DEFINE_SUBJ_BEG(pub_add_free_mem)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_GTASK, 0, NULL },
    { AC_SID_PLATDRV, 0, NULL },
    T_POLICY(add_free_mem)
AC_DEFINE_SUBJ_END(pub_add_free_mem)

AC_DEFINE_SUBJ_BEG(pub_adddynmemlist)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_GTASK, 0, NULL },
    T_POLICY(adddynmemlist)
AC_DEFINE_SUBJ_END(pub_adddynmemlist)

AC_DEFINE_SUBJ_BEG(pub_del_dyn_mem_list)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_GTASK, 0, NULL },
    T_POLICY(del_dyn_mem_list)
AC_DEFINE_SUBJ_END(pub_del_dyn_mem_list)

AC_DEFINE_SUBJ_BEG(pub_setprocsize)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_TALDR, 0, NULL },
    T_POLICY(setprocsize)
AC_DEFINE_SUBJ_END(pub_setprocsize)

AC_DEFINE_SUBJ_BEG(pub_mmap_scatter)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_PLATDRV, 0, NULL },
    T_POLICY(mmap_scatter)
AC_DEFINE_SUBJ_END(pub_mmap_scatter)

AC_DEFINE_SUBJ_BEG(pub_io_map)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_PLATDRV, 0, NULL },
    { AC_SID_DRV_TIMER, 0, NULL },
    { AC_SID_HMCCMGR, 0, NULL },
    T_POLICY(io_map)
AC_DEFINE_SUBJ_END(pub_io_map)

AC_DEFINE_SUBJ_BEG(pub_irq_acquire)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_PLATDRV, 0, NULL },
    { AC_SID_DRV_TIMER, 0, NULL },
    T_POLICY(irq_acquire)
AC_DEFINE_SUBJ_END(pub_irq_acquire)

AC_DEFINE_SUBJ_BEG(pub_sysctrl_tick)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_DRV_TIMER, 0, NULL },
    T_POLICY(sysctrl_tick)
AC_DEFINE_SUBJ_END(pub_sysctrl_tick)

AC_DEFINE_SUBJ_BEG(pub_sysctrl_local_irq)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_TEESMCMGR, 0, NULL },
    { AC_SID_GTASK, 0, NULL },
    { AC_SID_PLATDRV, 0, NULL },
    T_POLICY(sysctrl_local_irq)
AC_DEFINE_SUBJ_END(pub_sysctrl_local_irq)

AC_DEFINE_SUBJ_BEG(pub_teesmc_acquire)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_TEESMCMGR, 0, NULL },
    { AC_SID_PLATDRV, 0, NULL },
    { AC_SID_DRV_TIMER, 0, NULL },
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    { AC_SID_TEE_DRV_SERVER, 0, NULL },
#endif
    T_POLICY(teesmc_acquire)
AC_DEFINE_SUBJ_END(pub_teesmc_acquire)

AC_DEFINE_SUBJ_BEG(pub_pid2cref)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_PERF, 0, NULL },
    T_POLICY(pid2cref)
AC_DEFINE_SUBJ_END(pub_pid2cref)

AC_DEFINE_SUBJ_BEG(pub_dumpvregion)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    T_POLICY(dumpvregion)
AC_DEFINE_SUBJ_END(pub_dumpvregion)

AC_DEFINE_SUBJ_BEG(pub_map2task)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_GTASK, ARRAY_SIZE(g_map2task_gtask_objs), &g_map2task_gtask_acobjs },
    { AC_SID_PLATDRV, ARRAY_SIZE(g_map2task_platdrv_objs), &g_map2task_platdrv_acobjs },
    T_POLICY(map2task)
AC_DEFINE_SUBJ_END(pub_map2task)

AC_DEFINE_SUBJ_BEG(pub_unmap2task)
#ifdef DEF_ENG
    { AC_SID_SUPER, 0, NULL },
#endif
    { AC_SID_GTASK, 0, NULL },
    { AC_SID_PLATDRV, 0, NULL },
    { AC_SID_DRV_TIMER, 0, NULL },
    { AC_SID_HMCCMGR, 0, NULL },
    T_POLICY(unmap2task)
AC_DEFINE_SUBJ_END(pub_unmap2task)

AC_DEFINE_SUBJ_BEG(pub_push_rnd)
    { AC_SID_PLATDRV, 0, NULL },
    T_POLICY(push_rnd)
AC_DEFINE_SUBJ_END(pub_push_rnd)

AC_DEFINE_SUBJ_BEG(pub_mmap_physical)
#ifdef DEF_ENG
    { AC_SID_SUPER, ARRAY_SIZE(g_mmap_physical_cap), &g_mmap_physical_obj_all },
#endif
    { AC_SID_PLATDRV, ARRAY_SIZE(g_mmap_physical_cap), &g_mmap_physical_obj_all },
    { AC_SID_HMCCMGR, ARRAY_SIZE(g_mmap_physical_cap), &g_mmap_physical_obj_all },
    T_POLICY(mmap_physical)
AC_DEFINE_SUBJ_END(pub_mmap_physical)

AC_DEFINE_SUBJ_BEG(pub_channel_register)
    T_POLICY(channel_register)
AC_DEFINE_SUBJ_END(pub_channel_register)

AC_DEFINE_SUBJ_BEG(pub_channel_acquire)
    T_POLICY(channel_acquire)
AC_DEFINE_SUBJ_END(pub_channel_acquire)

AC_DEFINE_SUBJ_BEG(pub_map_secure)
AC_DEFINE_SUBJ_END(pub_map_secure)

AC_DEFINE_SUBJ_BEG(pub_map_nonsecure)
AC_DEFINE_SUBJ_END(pub_map_nonsecure)

#undef OPS_BEGIN
#undef OPS_DEF
#define OPS_BEGIN(OPS) OPS
#ifndef AC_USE_POLICY_DB
#define OPS_DEF(op)                                                                               \
    struct ac_static_operation ac_op_##op = { ACOP_##op, ARRAY_SIZE(ac_subj_##op), ac_subj_##op }; \
    struct ac_static_operation ac_op_pub_##op = { ACOP_##op, ARRAY_SIZE(ac_subj_pub_##op), ac_subj_pub_##op }; \
    struct ac_operation ac_op_dyn_##op   = { ACOP_##op, 0, NULL };
#else
#define OPS_DEF(op) { ACOP_##op, ARRAY_SIZE(ac_subj_##op), ac_subj_##op },
    const struct ac_operation g_local_operation[] = {
#endif

#include <ops_def/all_ops_def.h>

#ifdef AC_USE_POLICY_DB
}
;
AC_DEFINE_ARRAY_SIZE(g_local_operation);
#endif

#ifndef AC_USE_POLICY_DB
#define FILL_MAP(map)                                                                                  \
    struct ac_map g_ac_map_##map = { AC_MAP_##map, ARRAY_SIZE(g_ac_map_kv_##map), g_ac_map_kv_##map }; \
    struct ac_map g_ac_map_dyn_##map   = { AC_MAP_##map, 0, NULL };
#else
#define FILL_MAP(map) { AC_MAP_##map, ARRAY_SIZE(g_ac_map_kv_##map), g_ac_map_kv_##map },
        const struct ac_map g_local_map[] = {
#endif

#ifndef AC_USE_POLICY_DB
#define GET_MAP(map)                                  \
    struct ac_map *get_ac_map_##map()                 \
    {                                                 \
        return &g_ac_map_##map;                       \
    }                                                 \
    struct ac_map *get_ac_dyn_map_##map()             \
    {                                                 \
        return &g_ac_map_dyn_##map;                   \
    }
#define GET_KV(kv)                                                  \
    struct ac_map_key_value *get_kv_##kv(uint32_t *size)            \
    {                                                               \
        *size = ARRAY_SIZE(g_ac_map_kv_##kv);                       \
        return g_ac_map_kv_##kv;                                    \
    }
#else
#define GET_MAP(map)                                  \
    const ac_map *get_local_map                       \
    {                                                 \
        return &g_local_map;                          \
    }
#endif

FILL_MAP(uid_to_sid)
FILL_MAP(uuid_to_cred)
FILL_MAP(name_to_sid)

GET_MAP(uid_to_sid)
GET_MAP(uuid_to_cred)
GET_MAP(name_to_sid)

GET_KV(uuid_to_cred)
GET_KV(uid_to_sid)

#ifdef AC_USE_POLICY_DB
}
;
AC_DEFINE_ARRAY_SIZE(g_local_map);
#endif

#ifdef AC_USE_POLICY_DB
const struct ac_policy_db g_policy_db = {
    ARRAY_SIZE(g_local_operation),
    ARRAY_SIZE(g_local_map),
    ARRAY_SIZE(g_local_cap),
    g_local_operation,
    g_local_map,
    g_local_cap
};
#endif

#endif
