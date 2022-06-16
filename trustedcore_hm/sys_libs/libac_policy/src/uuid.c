/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: functions for uuid
 * Create: 2017-03-10
 */
#include <string.h>
#include <api/tee_common.h>
#include <security_ops.h>
#include <security_cap_def.h>
#include "ac_internal_idx.h"
#include "ac_obj_fn.h"
#include "ta_uuid.h"
#include "ac_policy.h"
#include "sid2uid.h"

#define WEAK __attribute__((weak))

/*
 * AC_UUID_MAX can't be used directly by applications and libraries built in
 * the main repository, because AC_UUID_MAX would be changed after release.
 * We compile this file in the sub-repository to make sure that we always get
 * the right uuid max value.
 */
int ac_get_uuid_max(void)
{
    return AC_UUID_MAX;
}

WEAK bool ac_taskmap2task_valid_subj_sid_vendor(uint64_t sid)
{
    (void)sid;
    return false;
}

bool ac_taskmap2task_valid_subj_sid(uint64_t sid)
{
    switch (sid) {
    case AC_SID_PLATDRV:
    case AC_SID_DRV_TIMER:
#if (defined TEE_SUPPORT_SSA_64BIT || defined TEE_SUPPORT_SSA_32BIT)
    case AC_SID_TEE_SERVICE_SSA:
#endif
        return true;
    default:
        return ac_taskmap2task_valid_subj_sid_vendor(sid);
    }
}

WEAK bool ac_map2task_valid_subj_sid_vendor(uint64_t sid)
{
    (void)sid;
    return false;
}

bool ac_map2task_valid_subj_sid(uint64_t sid)
{
    switch (sid) {
    case AC_SID_PLATDRV:
#if (defined TEE_SUPPORT_SSA_64BIT || defined TEE_SUPPORT_SSA_32BIT)
    case AC_SID_TEE_SERVICE_SSA:
#endif
#ifdef TEE_SUPPORT_HSM
    case AC_SID_TEE_SERVICE_HSM:
#endif
        return true;
    default:
        return ac_map2task_valid_subj_sid_vendor(sid);
    }
}

bool ac_ta_add_valid_obj(const char *obj)
{
    if (obj == NULL)
        return false;
    if (strncmp(obj, ".rtosck.tui", sizeof(".rtosck.tui")) != 0)
        return true;
    return false;
}

bool ac_teecall_valid_obj(uint8_t rights)
{
    uint8_t valid_rights = TEECALL_SET_KM_ROT_GROUP | TEECALL_GET_KM_ROT_GROUP;
    return (rights & ~valid_rights) == 0;
}

const struct ac_plc_obj_fn_set *ac_get_obj_fn_subo(uint64_t sub_type)
{
    switch (sub_type) {
    case ACOP_ta_add:
        return &g_ta_add_fn_set;
    case ACOP_unmap2task:
        return &g_unmap2task_fn_set;
    case ACOP_proc_status:
        return &g_proc_status_fn_set;
    case ACOP_get_uuid:
        return &g_get_uuid_fn_set;
    case ACOP_io_map:
        return &g_io_map_fn_set;
    case ACOP_irq_acquire:
        return &g_irq_acquire_fn_set;
    case ACOP_sysctrl_local_irq:
        return &g_sysctrl_local_irq_fn_set;
    case ACOP_teesmc_acquire:
        return &g_teesmc_acquire_fn_set;
    case ACOP_virt2phys:
        return &g_virt2phys_fn_set;
    case ACOP_map_secure:
        return &g_map_secure_fn_set;
    case ACOP_map_nonsecure:
        return &g_map_nonsecure_fn_set;
    default:
        break;
    }
    return &g_null_fn_set;
}
const struct ac_plc_obj_fn_set *ac_get_obj_fn_subc(uint64_t sub_type)
{
    if (sub_type == CAPTYPE_teecall)
        return &g_teecall_fn_set;
    return &g_null_fn_set;
}
const struct ac_plc_obj_fn_set *ac_get_obj_fn(uint8_t pri_type, uint64_t sub_type)
{
    switch (pri_type) {
    case 'o':
        return ac_get_obj_fn_subo(sub_type);
    case 'c':
        return ac_get_obj_fn_subc(sub_type);
    default:
        break;
    }
    return &g_null_fn_set;
}

int get_uid_by_sid(uint64_t sid, uid_t *uid)
{
    uint32_t i;
    const struct ac_map_key_value *map = get_ac_map_kv_uid_to_sid();
    uint32_t size = get_ac_map_kv_uid_to_sid_size();

    if (uid == NULL)
        return -1;

    for (i = 0; i < size; i++) {
        if (*((uint64_t *)map[i].value) == sid) {
            *uid = *((uid_t *)map[i].key);
            return 0;
        }
    }
    return -1;
}
