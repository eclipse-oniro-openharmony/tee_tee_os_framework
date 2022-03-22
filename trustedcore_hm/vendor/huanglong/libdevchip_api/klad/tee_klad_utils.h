/*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: klad basic utils impl.
* Author: Hisilicon security team
* Create: 2019-08-12
*/

#ifndef __API_KLAD_UTILS_H__
#define __API_KLAD_UTILS_H__

#include "tee_klad_define.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

hi_u32  get_queue_lenth(const hi_u32 read, const hi_u32 write, const hi_u32 size);

struct  klad_slot_table *get_slot_table(hi_void);
struct  klad_sw_base_ops *get_klad_sw_base_ops(hi_void);


hi_s32  klad_sw_r_get_raw(struct klad_sw_base *obj);
hi_s32  klad_sw_r_get(hi_handle handle, struct klad_sw_base **obj);
hi_void klad_sw_r_put(struct klad_sw_base *obj);

hi_s32  klad_sw_session_create(struct klad_sw_session **new_hw_session);
hi_s32  klad_sw_session_add_slot(struct klad_sw_session *hw_session, struct klad_slot *slot);
hi_s32  klad_sw_session_del_slot(struct klad_sw_session *hw_session, struct klad_slot *slot);
hi_s32  klad_sw_session_destroy(struct klad_sw_session *hw_session);

hi_s32 klad_slot_create(struct klad_slot **slot);
hi_s32 klad_slot_destroy(struct klad_slot *slot);
hi_s32 klad_slot_find(hi_handle handle, struct klad_slot **slot);
hi_s32 klad_slot_bind(hi_handle handle, struct klad_sw_base *obj);
hi_s32 klad_slot_get_robj(hi_handle handle, struct klad_sw_base **obj);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  // __API_KLAD_UTILS_H__

