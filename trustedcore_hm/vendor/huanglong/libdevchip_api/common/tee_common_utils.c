/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description : tee common utils impl
 */

#include "hi_log.h"
#include "stdarg.h"
#include "stdint.h"
#include <string.h>

#include "hmdrv.h"
#include "hm_msg_type.h"
#include "securec.h"

#include "tee_common_utils.h"
#include "hi_tee_module_id.h"
#include "hi_tee_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "tee_drv_common_ioctl.h"

static hi_s32 tee_common_ioctl(unsigned long cmd, hi_void *pri_args)
{
    unsigned int args[] = {
        (unsigned long)cmd,
        (unsigned long)(uintptr_t)pri_args,
    };

    return hm_drv_call(HI_TEE_SYSCALL_COMMON, args, ARRAY_SIZE(args));
}

hi_s32 tee_common_get_version_info(hi_char *version_info, hi_u32 len, hi_u32 total_size)
{
    hi_s32 ret;
    common_tee_version_info para_version = {0};

    common_check_pointer(version_info);

    para_version.total_size = total_size;

    ret = tee_common_ioctl(COMMON_TEE_IOCTL_GET_VERSION, &para_version);
    if (ret == HI_SUCCESS) {
        if (len <= strlen(para_version.version) || len > SECURE_OS_VERSION_LEN ||
            strlen(para_version.version) >= SECURE_OS_VERSION_LEN) {
            HI_ERR_COMMON("len is invalid!\n");
            return HI_FAILURE;
        } else {
            ret = memcpy_s(version_info, len, para_version.version, strlen(para_version.version) + 1);
            if (ret != EOK) {
                HI_ERR_COMMON("memcpy_s error!\n");
                return HI_FAILURE;
            }
        }
    }

    return ret;
}

