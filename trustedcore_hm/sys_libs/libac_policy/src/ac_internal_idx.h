/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: internal idx for ac
 * Create: 2017-03-10
 */

#ifndef LIBAC_AC_INTERNAL_IDX_H
#define LIBAC_AC_INTERNAL_IDX_H

#include "ac_idx.h"

enum ac_uuid_idx {
#define AC_UUID_ALT(x) AC_UUID_IDX_##x
#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
    AC_UUID_MAX
};

enum ac_sid_idx_uuid {
    AC_TA_SID_GUARD = AC_TA_SID_BASE - 1,
#define AC_UUID_ALT(x) AC_SID_##x
#undef LIBAC_AC_UUID_H /* we need to reuse data defined in ac_uuid.h */
#include "ac_uuid.h"
#undef AC_UUID_ALT
};

#endif
