/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: policy public defines.
 * Create: 2020-10
 */

#ifndef PUBLIC_TEECALL_H
#define PUBLIC_TEECALL_H

const cap_teecall_t g_pub_teecall_cap[MAX_PUB_CAP_NUM] = {
#ifdef DEF_ENG
    [AC_ARRAY_IDX_BUILTIN(SUPER)]      = { TEECALL_ALL_GROUP_PERMISSION },
#else
    [AC_ARRAY_IDX_BUILTIN(SUPER)]      = { 0x0 },
#endif
    [AC_ARRAY_IDX_BUILTIN(TEESMCMGR)]  = { TEECALL_GENERAL_GROUP_PERMISSION },
    [AC_ARRAY_IDX_BUILTIN(GTASK)]      = { TEECALL_GENERAL_GROUP_PERMISSION | TEECALL_GTASK_GROUP_PERMISSION |
                                           TEECALL_KERNEL_GROUP_PERMISSION },
    [AC_ARRAY_IDX_BUILTIN(PLATDRV)]    = { TEECALL_KERNEL_GROUP_PERMISSION | TEECALL_GET_SHAREMEM_GROUP_PERMISSION |
                                           TEECALL_VATOPA_GROUP_PERMISSION },
    [AC_ARRAY_IDX_BUILTIN(DRV_TIMER)]  = { TEECALL_KERNEL_GROUP_PERMISSION },
    [AC_ARRAY_IDX_BUILTIN(HMCCMGR)]    = { TEECALL_GENERAL_GROUP_PERMISSION },
};

static const struct ac_object g_teecall_obj[AC_SID_NUM] = {
#define AC_UID_ALT(x)                   \
    {                                   \
        0, &g_teecall_cap[AC_UID_IDX_##x] \
    }
#include "ac_uid.h"
#undef AC_UID_ALT
    { 0, &g_teecall_cap[AC_SID_BUILTIN_MAX] },
    { 0, &g_teecall_cap[AC_SID_BUILTIN_MAX + 1] },
    { 0, &g_teecall_cap[AC_SID_BUILTIN_MAX + 2] },
#define AC_UUID_ALT(x)                                        \
    {                                                         \
        0, &g_teecall_cap[AC_UUID_IDX_##x + AC_SID_BUILTIN_NUM] \
    }
#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
};

AC_DEFINE_TEECALL_SUBJ_BEG(teecall)
#define AC_UID_ALT(x)                               \
    {                                               \
        AC_SID_##x, 1, &g_teecall_obj[AC_UID_IDX_##x] \
    }
#include "ac_uid.h"
#undef AC_UID_ALT
    { AC_SID_TA_DEFAULT, 1, &g_teecall_obj[AC_SID_BUILTIN_MAX] },
    { AC_SID_NO_POLICY, 1, &g_teecall_obj[AC_SID_BUILTIN_MAX + 1] },
    { AC_SID_HAS_POLICY, 1, &g_teecall_obj[AC_SID_BUILTIN_MAX + 2] },
#define AC_UUID_ALT(x)                                                    \
    {                                                                     \
        AC_SID_##x, 1, &g_teecall_obj[AC_UUID_IDX_##x + AC_SID_BUILTIN_NUM] \
    }
#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
    AC_DEFINE_TEECALL_SUBJ_END(teecall)

#undef CAP_BEGIN
#undef CAP_DEF
#define CAP_BEGIN(CAPS) CAPS
#define CAP_DEF(cap)                                                                                \
    const struct ac_cap g_ac_cap_##cap = { CAPTYPE_##cap, ARRAY_SIZE(ac_subj_##cap), ac_subj_##cap }; \
    struct ac_cap g_ac_cap_dyn_##cap   = { CAPTYPE_##cap, 0, NULL };

#include <cap_def.h>

#endif
