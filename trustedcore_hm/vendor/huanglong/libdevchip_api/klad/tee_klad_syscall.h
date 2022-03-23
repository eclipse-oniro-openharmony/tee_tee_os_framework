/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: define API about key ladder driver
 * Author: linux SDK team
 * Create: 2019-8-13
 */
#ifndef __TEE_KLAD_SYSCALL_H__
#define __TEE_KLAD_SYSCALL_H__

#include <semaphore.h>
#include "tee_klad_define.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef enum {
    SYNCHRONIZE  = 0x01,
    ASYNCHRONIZE = 0x02,
} scene_cmd;

typedef enum {
    MSG_TYPE_COM   = 0x10,
    MSG_TYPE_TA    = 0x11,
    MSG_TYPE_FP    = 0x12,
    MSG_TYPE_NONCE = 0x13,
    MSG_TYPE_CLR   = 0x14,
    MSG_TYPE_EXIT  = 0x15,
} msg_type;

struct klad_args {
    hi_s32 ret_code;
    hi_u8  value[0x20];
};

typedef struct {
    sem_t sem;
    scene_cmd scene;
    msg_type type;
    hi_u32 len;
    hi_char *msg;
    callback_func call_back_func;
    hi_void *user_data;
    hi_u32 user_data_len;
} mq_data;

struct time_ns {
    hi_ulong tv_sec;
    hi_ulong tv_nsec;
};

hi_void get_time(struct time_ns *time);
hi_void get_cost(const hi_char *str, const struct time_ns *time_b, const struct time_ns *time_e);
hi_void get_curr_cost(const hi_char *str, const struct time_ns *time_b);

hi_s32 klad_fd(hi_void);
hi_s32 ctl_klad_init(hi_void);
hi_s32 ctl_klad_deinit(hi_void);

hi_void ctl_klad_msgq(hi_void);

hi_s32 ctl_klad_com_prepare(struct com_klad_slot *slot, hi_klad_com_entry *entry);
hi_s32 ctl_klad_com_attr_prepare(struct com_klad_slot *slot, hi_klad_create_attr *hkl_attr);

hi_s32 ctl_klad_fp_attr_prepare(struct fp_klad_slot *slot, hi_klad_create_attr *hkl_attr);

hi_s32 ctl_klad_com_startup(struct com_klad_slot *slot, const hi_klad_com_entry *entry);
hi_s32 ctl_klad_com_asynchronize_startup(struct com_klad_slot *slot, const klad_callback *call_back);

hi_s32 ctl_klad_ta_startup(struct ta_klad_slot *slot);
hi_s32 ctl_klad_fp_startup(struct fp_klad_slot *slot);
hi_s32 ctl_klad_fp_route(struct fp_klad_slot *slot);
hi_s32 ctl_klad_fp_crypto(struct fp_klad_slot *slot);
hi_s32 ctl_klad_nonce_startup(struct nonce_klad_slot *slot);
hi_s32 ctl_klad_clr_process(struct clr_route_slot *slot);

hi_s32 ctl_klad_com_create(hi_handle *handle, const hi_klad_create_attr *hkl_attr);
hi_s32 ctl_klad_ta_create(hi_handle *handle, const hi_klad_create_attr *hkl_attr);
hi_s32 ctl_klad_fp_create(hi_handle *handle, const hi_klad_create_attr *hkl_attr);
hi_s32 ctl_klad_nonce_create(hi_handle *handle, const hi_klad_create_attr *hkl_attr);

hi_s32 ctl_klad_com_destroy(hi_handle hw_handle);
hi_s32 ctl_klad_ta_destroy(hi_handle hw_handle);
hi_s32 ctl_klad_fp_destroy(hi_handle hw_handle);
hi_s32 ctl_klad_nonce_destroy(hi_handle hw_handle);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __TEE_KLAD_SYSCALL_H__ */

