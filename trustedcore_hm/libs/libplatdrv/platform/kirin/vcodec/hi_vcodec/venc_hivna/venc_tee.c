/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: vcodec secure os part
 * Author:
 * Create: 2019-12-1
 */

#include "venc_tee.h"

int SEC_VENC_MemRee2Tee(HI_U32 reeAddr, HI_U32 secShareFd, HI_U32 offset, HI_U32 datalen)
{
    HI_S32 ret;
    unsigned int normalVirtAddr = reeAddr;
    unsigned int bufId = (unsigned int)secShareFd;

    struct mem_chunk_list mcl = {0};
    mcl.protect_id = DRM_PROTECT_ID;
    mcl.buff_id = bufId;
    mcl.size = datalen;
    mcl.cache = UNCACHE_MODE;
    ret = sion_map_kernel(&mcl);
    if (ret != 0) {
        tloge("%d sion map kernel failed, ret: 0x%x\n", __LINE__, ret);
        return ret;
    }
    uintptr_t secVa = (uintptr_t)mcl.va;
    secVa += offset;
    TEE_MemMove((char *)secVa, (char *)(uintptr_t)normalVirtAddr, datalen);

    tlogi("datalen: %u, offset: %u \n", datalen, offset);
    ret = sion_unmap_kernel(&mcl);
    if (ret != 0) {
        tloge("ree2tee:unmap kernel failed, ret = %d\n", ret);
    }
    return ret;
}

int SEC_VENC_MemTee2Ree(HI_U32 reeAddr, HI_U32 secShareFd, HI_U32 offset, HI_U32 datalen)
{
    HI_S32 ret;
    unsigned int normalVirtAddr = reeAddr;
    unsigned int bufId = (unsigned int)secShareFd;

    struct mem_chunk_list mcl = {0};
    mcl.protect_id = DRM_PROTECT_ID;
    mcl.buff_id = bufId;
    mcl.size = datalen;
    mcl.cache = UNCACHE_MODE;
    ret = sion_map_kernel(&mcl);
    if (ret != 0) {
        tloge("%d sion map kernel failed, ret: 0x%x\n", __LINE__, ret);
        return ret;
    }
    uintptr_t secVa = (uintptr_t)mcl.va ;
    secVa += offset;
    TEE_MemMove((char *)(uintptr_t)normalVirtAddr, (char *)secVa, datalen);

    tlogi("copied tee2ree datalen: %u, offset: %u\n", datalen, offset);
    ret = sion_unmap_kernel(&mcl);
    if (ret != 0) {
        tloge("tee2ree:unmap kernel failed, ret = %d\n", ret);
    }
    return ret;
}

HI_S32 SEC_VENC_CFG_MASTER(enum SecVencState secVencState, HI_U32 coreId)
{
    if (secVencState == SEC_VENC_ON) {
        tlogd("set sec venc");
        ConfigSecurityMaster(coreId);
    } else {
        tlogd("set normal venc");
        ResetSecurityMaster(coreId);
    }
    return 0;
}
