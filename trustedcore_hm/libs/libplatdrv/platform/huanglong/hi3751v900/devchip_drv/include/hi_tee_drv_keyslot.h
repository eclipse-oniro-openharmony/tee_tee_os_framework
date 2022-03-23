/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Key slot drvier level head file.
 * Author: Linux SDK team
 * Create: 2019/06/22
 */

#ifndef __HI_DRV_KEYSLOT_H__
#define __HI_DRV_KEYSLOT_H__

#include "tee_drv_keyslot_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef hi_s32 (*ks_create)(const hi_keyslot_type slot_type, hi_handle *ks_handle);
typedef hi_s32 (*ks_destory)(const hi_keyslot_type slot_type, const hi_handle ks_handle);

typedef struct {
    ks_create ext_ks_create;
    ks_destory ext_ks_destory;
} ks_export_func_s;

hi_s32 hi_drv_ks_init(hi_void);
hi_s32 hi_drv_ks_deinit(hi_void);
hi_s32 hi_drv_ks_create(const hi_keyslot_type slot_type, hi_u32 *slot_num);
hi_s32 hi_drv_ks_destory(const hi_keyslot_type slot_type, const hi_u32 slot_num);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __HI_DRV_KEYSLOT_H__ */


