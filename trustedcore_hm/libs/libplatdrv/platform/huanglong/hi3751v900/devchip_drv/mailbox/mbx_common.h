/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: common interface in mailbox driver
 */
#ifndef _MBX_COMMON_H_
#define _MBX_COMMON_H_

#include "drv_mbx.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

hi_s32 mbx_tx(hi_u32 handle, const hi_u8 *msg, hi_u32 msg_len, hi_u32 *tx_len, hi_u32 timeout);
hi_s32 mbx_rx(hi_u32 handle, hi_u8 *msg, hi_u32 msg_len, hi_u32 *rx_len, hi_u32 timeout);
hi_s32 mbx_register_irq_callback(hi_u32 handle, session_callback func, hi_void *data);
hi_s32 mbx_open(hi_u32 session_id, hi_u32 rx_buf_size, hi_u32 tx_buf_size);
hi_s32 mbx_close(hi_u32 handle);
hi_s32 mbx_rx_msg(hi_void *rx_head_addr);
struct mailbox *get_mailbox_data(hi_void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _MBX_COMMON_H_ */
