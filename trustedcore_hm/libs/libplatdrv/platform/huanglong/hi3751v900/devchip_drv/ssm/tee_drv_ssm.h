/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.
 * Description: drv function file for Hisilicon SSM
 * Author: ssm group
 * Create: 2019/12/11
 * Notes:
 */

#ifndef __TEE_DRV_SSM_H__
#define __TEE_DRV_SSM_H__

#include "tee_drv_ssm_policy_table.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_module_id.h"
#include "hi_tee_drv_mem.h"
#include "hi_list.h"
#include "hi_tee_ssm.h"

#define hi_error_ssm(fmt...)        hi_tee_drv_hal_printf(fmt)
#define SECURE_INFO_MAX_NUM         240 /* Support 15(frame buffer numbers/per pipeline) x 16(pipeline) = 240 */

typedef enum {
    SSM_INTERNAL_BUF,
    SSM_SESSION_BUF,
    SSM_FRAME_BUF,
    SSM_INVALID_BUF,
} ssm_buf_type;

typedef struct {
    hi_tee_ssm_buffer_id buf_id;
    hi_u32 buf_tag;
} ssm_tag_2_id_map;

typedef struct {
    hi_s32 swi_id;
    hi_s32 (*syscall_handler)(TSK_REGS_S *regs, unsigned long long permissions);
} ssm_syscall_map;

typedef struct {
    hi_u32       tag;

    /* frame buffer info */
    hi_u32       buf_addr_high;
    hi_u32       buf_addr_low;
    hi_u32       buf_length;
    hi_u32       buf_reserved;

    /* frame info */
    hi_u32       resolution;
    hi_u32       min_resolution;
    hi_u32       frm_reserved;

    /* HDCP policy */
    hi_u32       hdcp_none_policy;
    hi_u32       hdcp_1_4_policy;
    hi_u32       hdcp_2_2_policy;
    hi_u32       hdcp_reserved;

    /* watermark control */
    hi_u32       wm_ctrl;
    hi_u32       vmx_wm_buf_addr_l;
    hi_u32       vmx_wm_buf_addr_h;
    hi_u32       vmx_wm_buf_length;
    hi_u32       nxg_wm_buf_addr_l;
    hi_u32       nxg_wm_buf_addr_h;
    hi_u32       nxg_wm_buf_length;
    hi_u32       wm_reserved;

    hi_u32       output_ctrl_ext;
    hi_u32       sec_info_reserved[16]; /* designed 16 bytes to spare */

    hi_u32       check_sum;
} hi_tee_ssm_secure_info;

typedef struct {
    hi_bool used;
} sec_info_status;

typedef struct {
    sec_info_status    status[SECURE_INFO_MAX_NUM];
    hi_u32             numbers_used;
    hi_tee_smmu_buf    secure_info_mem_header;
} hi_tee_ssm_sec_info_manager;

typedef struct {
    hi_tee_ssm_intent intent;
} hi_tee_ssm_attr;

typedef struct {
    hi_void    *priv_data;
    hi_u32      length;
} hi_tee_drv_ssm_private_data;

typedef struct {
    struct list_head list;
} hi_tee_drv_ssm_module_head;

typedef struct {
    struct list_head list;
} hi_tee_drv_ssm_buffer_info_head;

typedef struct {
    hi_handle                       session_handle;
    hi_tee_ssm_intent               intent;
    TEE_UUID                        uuid;
    hi_u32                          third_partner_sid;    /* CAS or DRM session ID */
    hi_u32                          third_partner_intent; /* CAS or DRM INTENT */
    hi_tee_drv_ssm_private_data     private_data;
    hi_tee_drv_ssm_module_head      cipher_head;
    hi_tee_drv_ssm_module_head      plcipher_head;
    hi_tee_drv_ssm_module_head      demux_head;
    hi_tee_drv_ssm_module_head      vdec_head;
    hi_tee_drv_ssm_buffer_info_head buffer_info_list_head[DRV_SSM_SESSION_BUF_TYPE_NUM];

    struct list_head list;
} hi_tee_drv_ssm_instance;

typedef struct {
    hi_handle module_handle;
    struct list_head list;
} hi_tee_drv_ssm_module_node;

typedef struct {
    hi_u64             buf_addr;
    hi_u64             buf_end_addr;
    hi_mod_id   src_mod_handle;
    hi_mod_id   dst_mod_handle;

    struct list_head list;
} hi_tee_drv_ssm_buffer_info_node;

typedef struct {
    hi_handle                 session_handle; /* session handle, invalid for frame buffer, should be set 0xFFFFFFFF */
    hi_handle                 module_handle;  /* module handle which module the buffer will be attached to */
    hi_tee_ssm_buffer_id      buf_id;         /* buffer ID */
    hi_u64                    si_addr;        /* Output parameter: Secure Info Addr, only valid for frame buffer */
} hi_tee_ssm_buf_attach_pre_params;

typedef struct {
    hi_handle               session_handle;
    hi_tee_ssm_buffer_id    buf_id;
    hi_u64                  buf_smmu_addr;
    hi_u32                  buf_len;
    hi_handle               module_handle;
} hi_tee_drv_ssm_buf_attach_info;

typedef struct {
    hi_handle                session_handle; /* session handle, only valid for session buffer */
    hi_handle                module_handle;  /* module handle which module the buffer will be attached to */
    hi_tee_ssm_buffer_id     buf_id;         /* buffer ID */
    hi_u64                   buf_addr;       /* buffer Addr */
    hi_u64                   buf_size;       /* buffer size */
} hi_tee_drv_ssm_buf_check_info;

#endif
