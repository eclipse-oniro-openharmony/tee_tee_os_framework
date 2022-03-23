/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee drv header for pvr
 */

#include "hi_type_dev.h"
#include "tee_drv_pvr.h"

#ifndef __TE_DRV_PVR_PRIV_H__
#define __TE_DRV_PVR_PRIV_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

hi_s32 drv_pvr_play_copy_ree_data_to_tee(hi_void *dst, hi_u32 dst_len, const hi_void *src, hi_u32 src_len);
hi_s32 drv_pvr_play_proc_tsdata(tee_pvr_play_tsdata_info *data_info, hi_void *data_addr);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
