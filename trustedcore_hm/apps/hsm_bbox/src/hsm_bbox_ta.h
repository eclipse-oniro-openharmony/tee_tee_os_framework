/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: heart beat head file
 * Author: huawei
 * Create: 2020-08-05
 */
#ifndef HSM_BBOX_TA_H
#define HSM_BBOX_TA_H

#ifdef STATIC_SKIP
#define STATIC
#else
#define STATIC static
#endif

#define ROOTSCAN_HAM                "hsm-ca"
#define ROOTSCAN_HSM_UID            0
#define HWHIAIUSER_UID              1000
#define HSM_CHECK_STATE_CMD         0x331C
#define HSM_NOTIFY_PRERESET_TA_CMD  0x5000
#define HSM_ACCELERATOR_CHECK_CMD   0x5001
#define HSM_PG_FG_INFO_CMD          0x6000
#define TEE_HSM_SRV_FUZZ            0x9005

#define READ_PG_INFO_LEN            8

#define OPEN_SESSION_PARA_NUM       4
#define HSM_INDEX0                  0
#define HSM_INDEX1                  1
#define HSM_INDEX2                  2
#define HSM_INDEX3                  3
#define MODULE_TYPE_MAX             0x3
#define DATA_TYPE_MAX               0x2

#define COMBINE_HI_32LO(hi, lo) ((uint64_t)(hi) << 32 | (uint32_t)(lo))

#endif
