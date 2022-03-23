/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: vcodec secure os part
 * Author:
 * Create: 2019-12-1
 */
#ifndef VENC_TEE_H
#define VENC_TEE_H

#include <secmem.h>
#include <tee_mem_mgmt_api.h>
#include "hi_type.h"
#include "tee_log.h"

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#define DRM_PROTECT_ID     0
#define UNCACHE_MODE       0

enum SecVencState {
    SEC_VENC_OFF,
    SEC_VENC_ON,
};

HI_S32 SEC_VENC_MemRee2Tee(HI_U32 reeAddr, HI_U32 secShareFd, HI_U32 offset, HI_U32 datalen);
HI_S32 SEC_VENC_MemTee2Ree(HI_U32 reeAddr, HI_U32 secShareFd, HI_U32 offset, HI_U32 datalen);
HI_S32 SEC_VENC_CFG_MASTER(enum SecVencState secVencState, HI_U32 coreId);

void ConfigSecurityMaster(HI_U32 coreId);
void ResetSecurityMaster(HI_U32 coreId);

#endif /* VENC_TEE_H */
