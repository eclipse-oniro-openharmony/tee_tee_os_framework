/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee pvr head file
 */

#ifndef __TEE_PVR_UTILS_H__
#define __TEE_PVR_UTILS_H__

#undef HI_LOG_D_MODULE_ID
#define HI_LOG_D_MODULE_ID             HI_ID_PVR

#include "hi_type_dev.h"
#include "hi_log.h"
#include "hi_tee_module_id.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define tee_pvr_err_code_def(errid)         (hi_u32)(((HI_LOG_D_MODULE_ID) << 16) | (errid))

/* general error */
#define HI_TEE_ERROR_PVR_BASE               tee_pvr_err_code_def(0)

/* not support the operation */
#define HI_TEE_ERROR_PVR_NOT_SUPPORT        tee_pvr_err_code_def(1)

/* null pointer */
#define HI_TEE_ERROR_PVR_NULL_PTR           tee_pvr_err_code_def(2)

/* the ts data is less than 47k, can't be got */
#define HI_TEE_ERROR_PVR_NO_ENOUGH_DATA     tee_pvr_err_code_def(3)

/* the inputed param is invalid */
#define HI_TEE_ERROR_PVR_INVALID_PARAM      tee_pvr_err_code_def(4)

/* malloc memory failed */
#define HI_TEE_ERROR_PVR_NO_MEM             tee_pvr_err_code_def(5)

/* invalid data length from demux */
#define HI_TEE_ERROR_PVR_INVALID_LEN        tee_pvr_err_code_def(6)

/* the un-used buffer is low */
#define HI_TEE_ERROR_PVR_LOW_BUFFER         tee_pvr_err_code_def(7)

/* index is more than ts data */
#define HI_TEE_ERROR_PVR_INDEX_MORE         tee_pvr_err_code_def(8)

/* no free channel left */
#define HI_TEE_ERROR_NO_CHANNEL             tee_pvr_err_code_def(9)

/* current channel is busy */
#define HI_TEE_ERROR_BUSY                   tee_pvr_err_code_def(10)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
