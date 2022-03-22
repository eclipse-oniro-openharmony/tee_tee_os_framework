/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: Tee version head file.
 */

#ifndef __HI_TEE_VERSION_H__
#define __HI_TEE_VERSION_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CFG_HI_TEE_IRDETO_SUPPORT
#define HI_TEE_SW_VERSION   "v1.1.9.0"
#else
#define HI_TEE_SW_VERSION   "v1.1.9.2"
#endif

#define MKSTR(exp) # exp
#define MKMARCOTOSTR(exp) MKSTR(exp)

#define SOS_VERSION_NUM  MKMARCOTOSTR(SOS_VERSION)
#define VERSION_STRING  MKMARCOTOSTR(SDK_VERSION)
#define MANUFACTURE_STRING  "HISILICON"
#define MSID_STRING  MKMARCOTOSTR(SOS_MSID)
#define CHIP_TYPE_STRING MKMARCOTOSTR(CHIP_TYPE_NAME)

/* This function returns the anti-roll-back number this is available for TEE from the software. */
hi_s32 hi_tee_get_anti_roll_back_version(hi_u32 *version);


/* This function returns strings about the version information. */
hi_char *hi_tee_get_version_info(hi_void);


/* This function returns strings about the manufacture information. */
hi_char *hi_tee_get_manufacture_info(hi_void);


/* This function returns strings about the MSID information. */
hi_char *hi_tee_get_msid_info(hi_void);


/* This function returns strings about the Chip Type information. */
hi_char *hi_tee_get_chip_type_info(hi_void);

#ifdef __cplusplus
}
#endif

#endif

