/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee pvr head file
 */

#ifndef __TEE_PVR_H__
#define __TEE_PVR_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* max buffer length */
#define TEE_PVR_MAX_BUF_LENGTH              (2 * 47 * 1024 * 1024)

enum tee_pvr_drv_ioctl_func_id {
    TEE_DRV_PVR_PLAYCOPYTOTEE,
    TEE_DRV_PVR_PLAYPROCTSDATA,
    TEE_DRV_PVR_MAX
};

typedef struct {
    hi_u32 ch;
    hi_mem_handle ns_addr_handle;
    hi_mem_handle sec_addr_handle;
    hi_u32 data_len;
    hi_u32 head_offset;
    hi_u32 end_offset;
    hi_u32 head_add;
    hi_u32 end_add;
} hi_tee_pvr_drv_ioctl_buf;

#define pvr_unused(x)   ((x) = (x))

hi_s32 tee_pvr_play_copy_from_ree(hi_u32 tsbuf, hi_mem_handle ns_addr_handle,
    hi_mem_handle sec_addr_handle, hi_u32 data_len);
hi_s32 tee_pvr_play_proc_ts_data(hi_mem_handle sec_addr_handle,
    hi_u32 head_offset, hi_u32 end_offset, hi_u32 head_add, hi_u32 end_add);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */


#endif
