/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mtk driver framework header file
 * Author: HeYanhong heyanhong2@huawei.com
 * Create: 2020-08-19
 */
#ifndef DRV_PAL_DRV_ERROR_H
#define DRV_PAL_DRV_ERROR_H

#define DRV_FWK_API_OK 0x0 /* Returns on successful execution of a function. */
#define DRV_FWK_API_IPCH_WRONG_CMD 0x1 /* IPCH command is not supported */
#define DRV_FWK_API_IPCH_CLIENT_NOT_EXISTED 0x2 /* IPCH client is not existed */
#define DRV_FWK_API_MAP_TASK_BUFFER_FAILED 0x3 /* IPCH fail to map client buffer */
#define DRV_FWK_API_MAP_HARDWARE_FAILED 0x4 /* Fail to map hardware region */
#define DRV_FWK_API_INVALIDATE_PARAMETERS 0x5 /* Parameters are not valid */
#define DRV_FWK_API_WRONG_CALL_FLOW 0x6 /* Call direction from secure driver to tee driver is not supported */
#define DRV_FWK_API_MALLOC_FAILED 0x7 /* Malloc failed, maybe run out of memory? */
#define DRV_FWK_API_UNMAP_HARDWARE_FAILED 0x8 /* Fail to unmap hardware region */
#define DRV_FWK_API_SMC_CALL_FAILED 0x9 /* Fail to send smc call */

#endif
