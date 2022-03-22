/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: Tee version impl.
 */

#include "stdarg.h"
#include "stdint.h"

#include "hi_tee_hal.h"

#include "hi_type_dev.h"
#include "hi_tee_version.h"
#include "hi_tee_errcode.h"

/* This function returns the anti-roll-back number this is available for TEE from the software. */
hi_s32 hi_tee_get_anti_roll_back_version(hi_u32 *version)
{
    if (version == HI_NULL) {
        return HI_ERR_NULL_PTR;
    }

    *version = SOS_VERSION;

    return HI_SUCCESS;
}

/* This function returns strings about the version information */
hi_char *hi_tee_get_version_info(hi_void)
{
    return VERSION_STRING;
}

/* This function returns strings about the manufacture information */
hi_char *hi_tee_get_manufacture_info(hi_void)
{
    return MANUFACTURE_STRING;
}

hi_char *hi_tee_get_msid_info(hi_void)
{
    return MSID_STRING;
}

/* This function returns strings about the Chip Type information */
hi_char *hi_tee_get_chip_type_info(hi_void)
{
    return CHIP_TYPE_STRING;
}

