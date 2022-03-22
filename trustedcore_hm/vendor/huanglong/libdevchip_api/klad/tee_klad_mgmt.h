/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: klad basic function impl.
 * Author: Linux SDK team
 * Create: 2020-05-13
 */

#ifndef __TEE_KLAD_MGMT_H__
#define __TEE_KLAD_MGMT_H__

#include "tee_klad_define.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

hi_s32 klad_slot_mgmt_init(hi_void);
hi_void klad_slot_mgmt_exit(hi_void);
hi_s32 klad_slot_mgmt_create_slot(hi_handle *handle);
hi_s32 klad_slot_mgmt_destroy_slot(hi_handle handle);
hi_s32 klad_slot_mgmt_create_instance(hi_handle handle);
hi_s32 klad_slot_mgmt_destroy_instance(hi_handle handle);
hi_s32 klad_slot_mgmt_attach_ks(hi_handle handle, hi_handle handle_ks);
hi_s32 klad_slot_mgmt_detach_ks(hi_handle handle, hi_handle handle_ks);
hi_s32 klad_slot_mgmt_ta_init(hi_handle handle);
hi_s32 klad_slot_mgmt_fp_init(hi_handle handle);
hi_s32 klad_slot_mgmt_nonce_init(hi_handle handle);
hi_s32 klad_slot_mgmt_clr_init(hi_handle handle);
hi_s32 klad_slot_mgmt_com_init(hi_handle handle);

struct klad_slot_mgmt *__get_klad_slot_mgmt(hi_void);
struct klad_slot_mgmt *get_klad_slot_mgmt(hi_void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __TEE_KLAD_MGMT_H__ */

