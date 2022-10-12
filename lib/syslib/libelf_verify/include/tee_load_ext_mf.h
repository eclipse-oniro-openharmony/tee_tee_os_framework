/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:  Tee-load-extension-manifest function declaration.
 * Author: yuanhao34@huawei.com
 * Create: 2021-7-7
 */
#ifndef GTASK_TEE_LOAD_EXT_MF_H
#define GTASK_TEE_LOAD_EXT_MF_H

#include <dyn_conf_common.h>
#include <dyn_conf_dispatch_inf.h>
#include "tee_defines.h"
#include "tee_elf_verify.h"
enum {
    UNSUPPORTED,
    TA_DISTRIBUTION,
    TA_API_LEVEL,
    SDK_VERSION,
    IS_LIB,
    SSA_ENUM_ENABLE,
    IS_DYN_CONF,
    TARGET_TYPE,
    TARGET_VERSION,
    SYS_VERIFY_TA,
    MEM_PAGE_ALIGN,
    HARD_WARE_TYPE,
    SRV_RELEASE_TA_RES,
    SRV_CRASH_CALLBACK,
    SRV_NEED_CREATE_MSG,
    SRV_NEED_RELEASE_MSG,
};

TEE_Result tee_secure_img_parse_manifest_extension(const char *extension, uint32_t extension_size,
                                                   manifest_extension_t *mani_ext, struct dyn_conf_t *dyn_conf);
#endif
