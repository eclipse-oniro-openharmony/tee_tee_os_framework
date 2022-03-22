/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, old msg function, should change
 * Create: 2019-11-14
 */
#ifndef DRIVER_SRE_MSG_H
#define DRIVER_SRE_MSG_H
#include <msg_ops.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

/*
 * legacy msg function, not support anymore
 * should use "__SRE_MsgQSend" instead
 */
uint32_t ipc_msg_qsend(uint32_t uw_msg_handle, uint32_t uw_msg_id, uint32_t uw_dst_pid, uint8_t uc_dst_qid);

/*
 * legacy msg function, not support anymore
 * should use "__SRE_MsgQRecv" instead
 */
uint32_t ipc_msg_q_recv(uint32_t *puw_msg_handle, uint32_t *puw_msg_id, uint32_t *puw_sender_pid, uint8_t uc_recv_qid,
                        uint32_t uw_timeout);

/*
 * legacy msg function, not support anymore
 * should use "__SRE_MsgSnd" instead
 */
uint32_t ipc_msg_snd(uint32_t uw_msg_id, uint32_t uw_dst_pid, const void *msgp, uint16_t size);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif /* DRIVER_SRE_MSG_H */
