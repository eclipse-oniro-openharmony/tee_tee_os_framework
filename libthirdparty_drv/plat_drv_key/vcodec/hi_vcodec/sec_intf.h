/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: added for hm-teeos
 * Author: hanxuanwei
 * Create: 2018-05-21
 */

#ifndef SEC_INTF
#define SEC_INTF

#include <sre_typedef.h> // UINT32
#include "tee_common.h"
#include "sre_typedef.h"
#include <stdint.h>

typedef signed int SINT32;

SINT32 SecVdecInit(UINT32 *args, UINT32 argsLen, const UINT32 *phyIofo, UINT32 size);
SINT32 SecVdecExit(UINT32 isSecure);
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660)
SINT32 SecVdecControl(SINT32 chanID, UINT32 cmdID, UINT32 *args, UINT32 argLen);
#else
SINT32 SecVdecControl(SINT32 chanID, UINT32 cmdID, UINT32 *args, UINT32 argLen, UINT32 *phyIofo, UINT32 size);
#endif
SINT32 SecVdecSuspend(VOID);
SINT32 SecVdecResume(VOID);
SINT32 SecVdecRunProcess(UINT32 args, UINT32 argLen);
#ifdef VCODEC_ENG_VERSION
SINT32 SecVdecReadProc(UINT64 page, SINT32 count);
SINT32 SecVdecWriteProc(UINT32 option, SINT32 value);
#endif
SINT32 SecVdecGetChanImage(SINT32 chanID, UINT32 *Image);

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660)
SINT32 SecVdecReleaseChanImage(SINT32 chanID, UINT64 Image);
#else
SINT32 SecVdecReleaseChanImage(SINT32 chanID, UINT32 *Image);
#endif

SINT32 SecVdecConfigInputBuffer(SINT32 chanID, UINT32 *phyAddr);


typedef struct {
    uint32_t hal_phyaddr;
    uint32_t share_phyaddr;
    uint32_t pmv_phyaddr;
    uint32_t scd_phyaddr;
    uint32_t ctx_phyaddr;
    uint32_t input_phyaddr;
} PHY_ADDR_INFO_S;

#endif
