/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: pvr TA
 * Author: sdk
 * Create: 2019-10-28
 */

#define TA_DEBUG

#include "hi_tee_hal.h"
#include "hi_type_dev.h"
#include "tee_pvr.h"

#define TEE_PVR_COPY_FROM_REE       32
#define TEE_PVR_PLAY_PROCESS_DATA   64
#define TEE_TIMESHIFT_BIT           32

__DEFAULT TEE_Result TA_CreateEntryPoint(hi_void)
{
    /* ree kernel will create the communication, no need to add other thread */
    return AddCaller_CA_exec((char *)"hisi_pvr_client", 0);
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(hi_u32 types, TEE_Param params[0x4], hi_void **session)
{
    pvr_unused(types);
    pvr_unused(params);
    pvr_unused(session);

    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(hi_void *session, hi_u32 cmd,
    hi_u32 types, TEE_Param params[0x4])
{
    hi_s32 ret;

    pvr_unused(session);
    pvr_unused(types);

    if (params == HI_NULL) {
        tloge("params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (cmd == TEE_PVR_COPY_FROM_REE) {
        hi_u64 dst_addr = ((hi_u64)params[0x0].value.b << TEE_TIMESHIFT_BIT) | (hi_u64)params[0x0].value.a;
        hi_u64 src_addr = ((hi_u64)params[0x1].value.b << TEE_TIMESHIFT_BIT) | (hi_u64)params[0x1].value.a;
        hi_u64 src_offset = ((hi_u64)params[0x2].value.a << TEE_TIMESHIFT_BIT) | (hi_u64)params[0x2].value.b;
        hi_u32 data_len = params[0x3].value.a;
        hi_u32 tsbuf = params[0x3].value.b;
        hi_mem_handle dst_addr_handle = {dst_addr, 0};
        hi_mem_handle src_addr_handle = {src_addr, src_offset};
        ret = tee_pvr_play_copy_from_ree(tsbuf, dst_addr_handle, src_addr_handle, data_len);
    } else if (cmd == TEE_PVR_PLAY_PROCESS_DATA) {
        hi_u64 dst_addr = ((hi_u64)params[0x0].value.b << TEE_TIMESHIFT_BIT) | (hi_u64)params[0x0].value.a;
        hi_u64 dst_offset = ((hi_u64)params[0x1].value.a << TEE_TIMESHIFT_BIT) | (hi_u64)params[0x1].value.b;
        hi_u32 head_offset = params[0x2].value.a;
        hi_u32 end_offset = params[0x2].value.b;
        hi_u32 head_add = params[0x3].value.a;
        hi_u32 end_add = params[0x3].value.b;
        hi_mem_handle sec_addr_handle = {dst_addr, dst_offset};
        ret = tee_pvr_play_proc_ts_data(sec_addr_handle, head_offset, end_offset, head_add, end_add);
    } else {
        ret = TEE_ERROR_BAD_PARAMETERS;
        tloge("Invalid command(%d)!\n", cmd);
    }

    return (TEE_Result)ret;
}


__DEFAULT hi_void TA_CloseSessionEntryPoint(hi_void *session)
{
    pvr_unused(session);
    return;
}

__DEFAULT hi_void TA_DestroyEntryPoint(hi_void)
{
    return;
}

