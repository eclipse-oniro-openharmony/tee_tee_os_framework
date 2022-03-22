/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2016-2019. All rights reserved.
 * Description: tee head file
 * Author: Hisilicon multimedia interface software group
 * Create: 2016-07-12
 */

#ifndef __HI_TEE_HDMITX_H__
#define __HI_TEE_HDMITX_H__

#include "hi_type_dev.h"

#ifdef __c_plus_plus
#if __c_plus_plus
extern "C" {
#endif
#endif /* __c_plus_plus */

typedef enum {
    HI_TEE_HDMITX_ID_0 = 0,
    HI_TEE_HDMITX_ID_1,
    HI_TEE_HDMITX_ID_MAX
} hi_tee_hdmitx_id;

typedef enum {
    HI_TEE_HDMITX_HDCP_NONE = 0, /* no hdcp is working */
    HI_TEE_HDMITX_HDCP14_SUCC,   /* hdcp1.4 auth success */
    HI_TEE_HDMITX_HDCP14_FAIL,   /* hdcp1.4 auth fail */
    HI_TEE_HDMITX_HDCP22_SUCC,   /* hdcp2.2 auth success */
    HI_TEE_HDMITX_HDCP22_FAIL,   /* hdcp2.2 auth fail */
    HI_TEE_HDMITX_HDCP23_SUCC,   /* hdcp2.3 auth success */
    HI_TEE_HDMITX_HDCP23_FAIL,   /* hdcp2.3 auth fail */
    HI_TEE_HDMITX_HDCP_MAX
} hi_tee_hdmitx_hdcp_status;

typedef enum {
    HI_TEE_HDMITX_HDCP_LEVEL_NONE = 0, /* no hdcp monitoring */
    HI_TEE_HDMITX_HDCP_LEVEL_1,        /* hdcp1.X or hdcp2.X allowed output */
    HI_TEE_HDMITX_HDCP_LEVEL_2,        /* only hdcp2.X allowed output */
    HI_TEE_HDMITX_HDCP_LEVEL_MAX
} hi_tee_hdmitx_hdcp_level;

typedef struct {
    hi_u32 down_scal_width;
    hi_u32 down_scal_height;
} hi_tee_hdmitx_status;

typedef struct {
    hi_bool hdcp14_support;
    hi_bool hdcp22_support;
    hi_bool hdcp23_support;
} hi_tee_hdmitx_hdcp_caps;

typedef struct {
    hi_u8 *srm_data;
    hi_u32 srm_len;
} hi_tee_hdmitx_srm;

/* Create handle for setting hdcp strategy */
hi_s32 hi_tee_hdmitx_create_handle(hi_handle *hdmitx_handle, const hi_tee_hdmitx_id hdmitx_id);

/* Destroy handle for setting hdcp strategy */
hi_s32 hi_tee_hdmitx_destroy_handle(const hi_handle hdmitx_handle);

hi_s32 hi_tee_hdmitx_set_hdcp_strategy(const hi_handle hdmitx_handle, const hi_tee_hdmitx_hdcp_level hdcp_level);

/* Get hdcp strategy from drm, it is called by drm, it can be call more time */
hi_s32 hi_tee_hdmitx_get_hdcp_strategy(const hi_handle hdmitx_handle, hi_tee_hdmitx_hdcp_level *hdcp_level);

hi_s32 hi_tee_hdmitx_get_hdcp_status(const hi_tee_hdmitx_id hdmitx_id, hi_tee_hdmitx_hdcp_status *hdcp_status);

/*
 * Descrition: get HDCP capability
 * Param[out]: hdcp_caps  hdcp caps
 *                        hdcp14_support: support HDCP1.4 or not
 *                        hdcp22_support: support HDCP2.2 or not
 *                        hdcp23_support: support HDCP2.3 or not
 */
hi_s32 hi_tee_hdmitx_get_hdcp_caps(const hi_tee_hdmitx_id hdmitx_id, hi_tee_hdmitx_hdcp_caps *hdcp_caps);

hi_s32 hi_tee_hdmitx_set_srm(const hi_tee_hdmitx_id hdmitx_id, hi_tee_hdmitx_srm *srm);

hi_s32 hi_tee_hdmitx_get_status(const hi_tee_hdmitx_id hdmitx_id, hi_tee_hdmitx_status *status);

#ifdef __c_plus_plus
#if __c_plus_plus
}
#endif
#endif /* __c_plus_plus */
#endif /* __HI_TEE_HDMITX_H__ */

