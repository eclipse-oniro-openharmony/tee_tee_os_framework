/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Keyladder drvier level head file.
 * Author: linux SDK team
 * Create: 2019/07/23
 */

#ifndef __HI_DRV_KLAD_H__
#define __HI_DRV_KLAD_H__

#include "tee_drv_klad_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/*************************** structure definition ****************************/
/** \addtogroup      KLAD */
/** @{ */  /** <!-- [KLAD] */

hi_s32 klad_drv_mod_init(hi_void);

typedef struct {
    hi_handle ks_handle;
    hi_klad_attr attr;
    hi_klad_clear_key clr_key;
} klad_clear_cw_param;

typedef struct {
    hi_handle ks_handle;
    hi_bool is_odd;                    /* odd or even key flag. */
    hi_u8  iv[HI_KLAD_MAX_IV_LEN];
} klad_clear_iv_param;

typedef hi_s32(*klad_clear_cw_func)(const klad_clear_cw_param *clear_cw);

typedef hi_s32(*klad_clear_iv_func)(const klad_clear_iv_param *clear_iv);

typedef struct {
    klad_clear_cw_func klad_set_clear_key;
    klad_clear_iv_func klad_set_clear_iv;   /* set iv only used for tscipher. */
} klad_export_func;

hi_s32 hi_drv_klad_clear_cw(const klad_clear_cw_param *clear_cw);

hi_s32 hi_drv_klad_clear_iv(const klad_clear_iv_param *clear_iv);

hi_s32 hi_tee_drv_klad_creat(hi_handle *handle);
hi_s32 hi_tee_drv_klad_destroy(hi_handle handle);

hi_s32 hi_tee_drv_klad_attach(hi_handle handle, hi_handle target);
hi_s32 hi_tee_drv_klad_detach(hi_handle handle, hi_handle target);

hi_s32 hi_tee_drv_klad_set_attr(hi_handle handle, const hi_klad_attr *attr);
hi_s32 hi_tee_drv_klad_get_attr(hi_handle handle, hi_klad_attr *attr);

hi_s32 hi_tee_drv_klad_set_session_key(hi_handle handle, const hi_klad_session_key *key);
hi_s32 hi_tee_drv_klad_set_content_key(hi_handle handle, const hi_klad_content_key *key);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_DRV_KLAD_H__ */

