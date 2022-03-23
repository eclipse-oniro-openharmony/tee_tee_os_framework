/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: pvr api function definition.
 * Author: sdk
 * Create: 2019/10/28
 */

#include "hi_type_dev.h"

#ifndef __TEE_DRV_PVR_H__
#define __TEE_DRV_PVR_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct tee_pvr_play_tsdata_info_ {
    hi_u32 head_offset;
    hi_u32 head_add;
    hi_u32 end_offset;
    hi_u32 end_add;
} tee_pvr_play_tsdata_info;

hi_s32 tee_drv_pvr_play_copy_from_ree(hi_u32 tsbuf, hi_mem_handle ns_addr_handle,
    hi_mem_handle sec_addr_handle, hi_u32 data_len);
hi_s32 tee_drv_pvr_play_proc_ts_data(hi_mem_handle sec_addr_handle,
    hi_u32 head_offset, hi_u32 end_offset, hi_u32 head_add, hi_u32 end_add);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
