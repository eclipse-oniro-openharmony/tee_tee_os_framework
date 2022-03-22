/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: structure for target_type defined in manifest.txt
 * Create: 2021-07-13
 */

#ifndef LIBSPAWN_COMMON_INCLUDE_TARGET_TYPE_H
#define LIBSPAWN_COMMON_INCLUDE_TARGET_TYPE_H

#include <stdint.h>

/* should match with target_type defined in manifest.txt */
enum target_type {
    TA_TARGET_TYPE = 0,
    DRV_TARGET_TYPE = 1,
    DYN_LIB_TARGET_TYPE = 2,
    SRV_TARGET_TYPE = 3,
    CLIENT_TARGET_TYPE = 4,
    MAX_TARGET_TYPE,
};

#endif
