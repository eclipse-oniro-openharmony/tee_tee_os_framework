/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: policy public defines.
 * Create: 2020-10
 */

#ifndef PUBLIC_DEFINES_H
#define PUBLIC_DEFINES_H

#include "ac_policy.h"

const bool g_eng_policy = false;

#define AC_STATIC_ASSERT(condition, name) typedef int g_static_assert_##name[1 - 2 * (int)((condition) == 0)]
AC_STATIC_ASSERT(AC_UID_BUILTIN_MAX <= TA_DEFAULT_UID, AC_UID);
AC_STATIC_ASSERT(AC_SID_BUILTIN_MAX <= AC_SID_TA_DEFAULT, AC_SID);

#define AC_DEFINE_ARRAY_SIZE(array) const size_t array##_size = ARRAY_SIZE(array);

#define AC_DEFINE_TEECALL_SUBJ_BEG(OP) struct ac_subject ac_subj_##OP[] = {
#define AC_DEFINE_TEECALL_SUBJ_END(OP) \
}                                      \
;                                      \

#define AC_DEFINE_SUBJ_BEG(OP) struct ac_static_subject ac_subj_##OP[] = {
#define AC_DEFINE_SUBJ_END(OP) \
}                              \
;                              \
AC_DEFINE_ARRAY_SIZE(ac_subj_##OP);

#define T_POLICY(OP)

#define TEECALL_GENERAL_GROUP_PERMISSION TEECALL_GENERAL_GROUP
#define TEECALL_GTASK_GROUP_PERMISSION    TEECALL_GTASK_GROUP
#define TEECALL_SET_KM_ROT_GROUP_PERMISSION  TEECALL_SET_KM_ROT_GROUP
#define TEECALL_GET_KM_ROT_GROUP_PERMISSION  TEECALL_GET_KM_ROT_GROUP
#define TEECALL_GET_SHAREMEM_GROUP_PERMISSION     TEECALL_GET_SHAREMEM_GROUP
#define TEECALL_KERNEL_GROUP_PERMISSION  TEECALL_KERNEL_GROUP
#define TEECALL_VATOPA_GROUP_PERMISSION  TEECALL_VATOPA_GROUP
#define TEECALL_SYSMGR_GROUP_PERMISSION TEECALL_SYSMGR_GROUP
#define TEECALL_ALL_GROUP_PERMISSION     ((uint8_t)-1)

static const TEE_UUID g_uuid[] = {
#define AC_UUID_ALT(x) x
#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
};

static const cred_t g_cred[] = {
#define AC_UUID_ALT(x)                                \
    {                                                 \
        (AC_UUID_IDX_##x + AC_TA_UID_BASE), OTHER_GID \
    }
#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
};

struct ac_map_key_value g_ac_map_kv_uuid_to_cred[] = {
#define AC_UUID_ALT(x)                                 \
    {                                                  \
        &g_uuid[AC_UUID_IDX_##x], &g_cred[AC_UUID_IDX_##x] \
    }

#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
};
AC_DEFINE_ARRAY_SIZE(g_ac_map_kv_uuid_to_cred);

#define AC_UID_BUILTIN_NUM (AC_UID_BUILTIN_MAX + AC_FIXED_SID_NUM)
#define AC_UID_NUM         (AC_UID_BUILTIN_NUM + AC_UUID_MAX)
#define AC_SID_BUILTIN_NUM (AC_SID_BUILTIN_MAX + AC_FIXED_SID_NUM)
#define AC_SID_NUM         (AC_SID_BUILTIN_NUM + AC_UUID_MAX)

#define AC_ARRAY_IDX_BUILTIN(x) AC_UID_IDX_##x
#define AC_ARRAY_IDX(x)         (AC_UUID_IDX_##x + AC_SID_BUILTIN_NUM)

static const uint64_t g_sids[] = {
#define AC_UID_ALT(x) AC_SID_##x
#include "ac_uid.h"
#undef AC_UID_ALT

    AC_SID_TA_DEFAULT,
    AC_SID_NO_POLICY,
    AC_SID_HAS_POLICY,

#define AC_UUID_ALT(x) AC_SID_##x
#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
};

static const uid_t g_uids[] = {
#define AC_UID_ALT(x) AC_UID_IDX_##x
#include "ac_uid.h"
#undef AC_UID_ALT

    TA_DEFAULT_UID,
    AC_UID_NO_POLICY,
    AC_UID_HAS_POLICY,

#define AC_UUID_ALT(x) (AC_UUID_IDX_##x + AC_TA_UID_BASE)
#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
};

struct ac_map_key_value g_ac_map_kv_uid_to_sid[] = {
#define AC_UID_ALT(x)                            \
    {                                            \
        &g_uids[AC_UID_IDX_##x], &g_sids[AC_SID_##x] \
    }
#include "ac_uid.h"
#undef AC_UID_ALT

    { &g_uids[AC_UID_BUILTIN_MAX], &g_sids[AC_SID_BUILTIN_MAX] },
    { &g_uids[AC_UID_BUILTIN_MAX + 1], &g_sids[AC_SID_BUILTIN_MAX + 1] },
    { &g_uids[AC_UID_BUILTIN_MAX + 2], &g_sids[AC_SID_BUILTIN_MAX + 2] },

#define AC_UUID_ALT(x)                                                                           \
    {                                                                                            \
        &g_uids[AC_UUID_IDX_##x + AC_UID_BUILTIN_NUM], &g_sids[AC_UUID_IDX_##x + AC_SID_BUILTIN_NUM] \
    }
#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
};
AC_DEFINE_ARRAY_SIZE(g_ac_map_kv_uid_to_sid);

struct ac_map_key_value *get_ac_map_kv_uid_to_sid()
{
    return g_ac_map_kv_uid_to_sid;
}

uint32_t get_ac_map_kv_uid_to_sid_size()
{
    return g_ac_map_kv_uid_to_sid_size;
}

struct ac_map_key_value g_ac_map_kv_name_to_sid[] = {
#define AC_UID_ALT(x)         \
    {                         \
#x, &g_sids[AC_SID_##x] \
    }
#include "ac_uid.h"
#undef AC_UID_ALT

    { "TA_DEFAULT", &g_sids[AC_SID_BUILTIN_MAX] },
    { "NO_POLICY", &g_sids[AC_SID_BUILTIN_MAX + 1] },
    { "HAS_POLICY", &g_sids[AC_SID_BUILTIN_MAX + 2] },

#define AC_UUID_ALT(x)                                  \
    {                                                   \
#x, &g_sids[AC_UUID_IDX_##x + AC_SID_BUILTIN_NUM] \
    }
#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
};
AC_DEFINE_ARRAY_SIZE(g_ac_map_kv_name_to_sid);

#endif
