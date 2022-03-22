/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description :Module tee hdmitx head drivers.
 * Author : Hisilicon multimedia interface software group
 * Created : 2020-06-20
 */

#ifndef __HI_TEE_DRV_HDMITX_H__
#define __HI_TEE_DRV_HDMITX_H__

typedef enum hdmitx_id {
    HI_TEE_DRV_HDMITX_ID_0,
    HI_TEE_DRV_HDMITX_ID_1,
} hi_tee_drv_hdmitx_id;

typedef enum hdmitx_hotplug_status {
    HI_TEE_DRV_HDMITX_HOTPLUG_DETECTING,
    HI_TEE_DRV_HDMITX_HOTPLUG_IN,
    HI_TEE_DRV_HDMITX_HOTPLUG_OUT,
    HI_TEE_DRV_HDMITX_HOTPLUG_DET_FAIL,
} hi_tee_drv_hdmitx_hotplug_status;

typedef enum {
    HI_TEE_DRV_HDMITX_RSEN_DISCONNECT,
    HI_TEE_DRV_HDMITX_RSEN_CONNECT,
    HI_TEE_DRV_HDMITX_RSEN_DET_FAIL,
} hi_tee_drv_hdmitx_rsen_status;

typedef struct hdmitx_status {
    hi_tee_drv_hdmitx_hotplug_status hotplug;
    hi_tee_drv_hdmitx_rsen_status rxsen;
    hi_bool output_en;
} hi_tee_drv_hdmitx_status;

typedef enum {
    HI_TEE_DRV_HDMITX_HDCP_VERSION_NONE,
    HI_TEE_DRV_HDMITX_HDCP_VERSION_1X,
    HI_TEE_DRV_HDMITX_HDCP_VERSION_2X
} hi_tee_drv_hdmitx_hdcp_ver;

typedef struct hdmitx_hdcp_status {
    hi_bool auth_start;                   /* HDCP authentication start. */
    hi_bool auth_success;                 /* HDCP authentication success. */
    hi_tee_drv_hdmitx_hdcp_ver work_version;  /* HDCP authentication version. */
} hi_tee_drv_hdmitx_hdcp_status;

#define HI_TEE_DRV_HDMITX_HDCP_BKSV            5
#define HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX   127
#define HI_TEE_DRV_HDMITX_HDCP_RECVID          5
#define HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX 31

typedef struct hdcp14_downstream_info {
    hi_bool downstream_is_rpt;
    hi_u8 depth;
    hi_u8 dev_cnt;
    hi_bool max_devs_exceeded;
    hi_bool max_cascade_exceeded;
    hi_u8 bksv[HI_TEE_DRV_HDMITX_HDCP_BKSV];
    hi_u8 bksv_list[HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX][HI_TEE_DRV_HDMITX_HDCP_BKSV];
} hi_tee_drv_hdmitx_hdcp14_downstream_info;

typedef struct hdcp2x_downstream_info {
    hi_bool downstream_is_rpt;
    hi_u8 depth;
    hi_u8 dev_cnt;
    hi_bool max_devs_exceeded;
    hi_bool max_cascade_exceeded;
    hi_bool hdcp20_repeater_downstream;
    hi_bool hdcp1x_device_downstream;
    hi_u8 recvid[HI_TEE_DRV_HDMITX_HDCP_RECVID];
    hi_u8 recvid_list[HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX][HI_TEE_DRV_HDMITX_HDCP_RECVID];
} hi_tee_drv_hdmitx_hdcp2x_downstream_info;

typedef enum hdmitx_event {
    HI_TEE_DRV_HDMITX_EVENT_PLUG_IN,
    HI_TEE_DRV_HDMITX_EVENT_PLUG_OUT,
    HI_TEE_DRV_HDMITX_EVENT_CONNECT,
    HI_TEE_DRV_HDMITX_EVENT_DISCONNECT,
    /* This event notify while starting hdcp logic, ingore compability delay time between starting & plug in */
    HI_TEE_DRV_HDMITX_EVENT_START_AUTH,
    HI_TEE_DRV_HDMITX_EVENT_DOWNSTREAM_INFO_READY,
    HI_TEE_DRV_HDMITX_EVENT_MAX
} hi_tee_drv_hdmitx_event;

typedef hi_void (*hi_tee_drv_hdmitx_callback_pfn)(hi_tee_drv_hdmitx_id id,
    hi_tee_drv_hdmitx_event type, hi_void *private_data);

typedef struct hdmitx_callback {
    hi_tee_drv_hdmitx_callback_pfn func;
    hi_void *private;
} hi_tee_drv_hdmitx_callback;

typedef enum hdcp_stream_id {
    HI_TEE_DRV_HDMITX_HDCP_STREAM_ID_TYPE0,
    HI_TEE_DRV_HDMITX_HDCP_STREAM_ID_TYPE1,
} hi_tee_drv_hdmitx_hdcp_stream_id;

hi_s32 hi_tee_hdmitx_register_callback(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_callback *callback_func);
hi_s32 hi_tee_hdmitx_unregister_callback(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_callback *callback_func);
hi_s32 hi_tee_hdmitx_set_stream_id(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_hdcp_stream_id stream_id);
hi_s32 hi_tee_hdmitx_get_status(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_status *status);
hi_s32 hi_tee_hdmitx_get_hdcp_status(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_hdcp_status *hdcp_status);
hi_s32 hi_tee_hdmitx_get_hdcp14_downstream_info(hi_tee_drv_hdmitx_id id,
    hi_tee_drv_hdmitx_hdcp14_downstream_info *info);
hi_s32 hi_tee_hdmitx_get_hdcp2x_downstream_info(hi_tee_drv_hdmitx_id id,
    hi_tee_drv_hdmitx_hdcp2x_downstream_info *info);

#endif /* __HI_TEE_DRV_HDMITX_H__ */
