/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: klad basic function impl.
 * Author: Linux SDK team
 * Create: 2019/08/12
 */

#ifndef __TEE_KLAD_FUNC_H__
#define __TEE_KLAD_FUNC_H__

#include "tee_klad_define.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

hi_s32 klad_slot_com_create_impl(struct com_klad_slot *slot);
hi_s32 klad_slot_com_start_impl(struct com_klad_slot *slot);
/*
 * API : klad software instance defination.
 */
hi_s32 klad_slot_com_set_rootkey_attr(hi_handle handle, const hi_rootkey_attr *rootkey);
hi_s32 klad_slot_com_get_rootkey_attr(hi_handle handle, hi_rootkey_attr *rootkey);
hi_s32 klad_slot_com_set_attr(hi_handle handle, const hi_klad_attr *attr);
hi_s32 klad_slot_com_get_attr(hi_handle handle, hi_klad_attr *attr);
hi_s32 klad_slot_com_set_session_key(hi_handle handle, const hi_klad_session_key *session_key);
hi_s32 klad_slot_com_set_content_key(hi_handle handle, const hi_klad_content_key *content_key);
hi_s32 klad_slot_com_start(hi_handle handle);
hi_s32 klad_slot_com_async_start(hi_handle handle, const klad_callback *call_back);
hi_s32 klad_slot_com_stop(hi_handle handle);
struct klad_com_ops *get_sw_com_klad_slot_ops(hi_void);

hi_s32 klad_slot_fp_set_attr(hi_handle handle, const hi_klad_attr *attr);
hi_s32 klad_slot_fp_get_attr(hi_handle handle, hi_klad_attr *attr);
hi_s32 klad_slot_fp_set_session_key(hi_handle handle, const hi_klad_session_key *session_key);
hi_s32 klad_slot_fp_set_fp_key(hi_handle handle, const hi_klad_fp_key *fp_key);
hi_s32 klad_slot_fp_route(hi_handle handle);
hi_s32 klad_slot_fp_start(hi_handle handle);
hi_s32 klad_slot_fp_enc(hi_handle handle, hi_u8 *enc_key, hi_u32 enc_key_len);
hi_s32 klad_slot_fp_stop(hi_handle handle);
struct klad_fp_ops *get_sw_fp_klad_slot_ops(hi_void);

hi_s32 klad_slot_ta_set_attr(hi_handle handle, const hi_klad_attr *attr);
hi_s32 klad_slot_ta_get_attr(hi_handle handle, hi_klad_attr *attr);
hi_s32 klad_slot_ta_set_session_key(hi_handle handle, const hi_klad_ta_key *ta_key);
hi_s32 klad_slot_ta_set_trans_data(hi_handle handle, const hi_klad_trans_data *trans_data);
hi_s32 klad_slot_ta_set_content_key(hi_handle handle, const hi_klad_ta_key *ta_key);
hi_s32 klad_slot_ta_start(hi_handle handle);
hi_s32 klad_slot_ta_stop(hi_handle handle);
struct klad_ta_ops *get_sw_ta_klad_slot_ops(hi_void);

hi_s32 klad_slot_nonce_set_attr(hi_handle handle, const hi_klad_attr *attr);
hi_s32 klad_slot_nonce_get_attr(hi_handle handle, hi_klad_attr *attr);
hi_s32 klad_slot_nonce_set_session_key(hi_handle handle, const hi_klad_session_key *session_key);
hi_s32 klad_slot_nonce_set_nonce_key(hi_handle handle, const hi_klad_nonce_key *nonce_key);
hi_s32 klad_slot_nonce_start(hi_handle handle);
hi_s32 klad_slot_nonce_stop(hi_handle handle);
struct klad_nonce_ops *get_sw_nonce_klad_slot_ops(hi_void);

hi_s32 klad_slot_clr_set_attr(hi_handle handle, const hi_klad_attr *attr);
hi_s32 klad_slot_clr_get_attr(hi_handle handle, hi_klad_attr *attr);
hi_s32 klad_slot_clr_set_key(hi_handle handle, const hi_klad_clear_key *clr_key);
hi_s32 klad_slot_clr_start(hi_handle handle);
hi_s32 klad_slot_clr_stop(hi_handle handle);
struct klad_clr_route_ops *get_sw_clr_route_slot_ops(hi_void);

hi_s32 klad_slot_instance_init(hi_handle handle, hi_klad_type klad);
hi_bool klad_slot_instance_initialzed(hi_handle handle);

hi_s32 klad_slot_instance_set_attr(hi_handle handle, const hi_klad_attr *attr);
hi_s32 klad_slot_instance_get_attr(hi_handle handle, hi_klad_attr *attr);

hi_s32 klad_slot_instance_set_rootkey_attr(hi_handle handle, const hi_rootkey_attr *rootkey_attr);
hi_s32 klad_slot_instance_get_rootkey_attr(hi_handle handle, hi_rootkey_attr *rootkey_attr);

hi_s32 klad_slot_instance_attach(hi_handle handle, hi_handle target);
hi_s32 klad_slot_instance_detach(hi_handle handle, hi_handle target);

hi_s32 klad_slot_instance_set_session_key(hi_handle handle, const hi_klad_session_key *session_key);
hi_s32 klad_slot_instance_set_content_key(hi_handle handle, const hi_klad_content_key *content_key);
hi_s32 klad_slot_instance_start(hi_handle handle);
hi_s32 klad_slot_instance_async_start(hi_handle handle, const klad_callback *call_back);
hi_s32 klad_slot_instance_stop(hi_handle handle);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __TEE_KLAD_FUNC_H__ */

