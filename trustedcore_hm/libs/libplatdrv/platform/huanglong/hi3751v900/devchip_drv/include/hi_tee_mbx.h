/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.
 * Description: mailbox export interface definition.
 */
#ifndef _HI_TEE_MAILBOX_H_
#define _HI_TEE_MAILBOX_H_

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cpluscplus */

enum cpu_id {
    HPP = 0,
    TPP,
    TCPU,
    ACPU,
    VMCU0,
    VMCU1,
    CPU_MAX,
};

#define GEN_MBX_SESSION(side0, side1, num) \
        (((num) & 0xFF) << 8 | ((side0) & 0xF) << 4 | ((side1) & 0xF))

/* define session ID for user */
#define HI_MBX_ACPU2HIL_BOOT            GEN_MBX_SESSION(HPP, ACPU, 1)
#define HI_MBX_ACPU2HRF_BOOT            GEN_MBX_SESSION(HPP, ACPU, 2)
#define HI_MBX_ACPU2HRF_ACPU_DVFS       GEN_MBX_SESSION(HPP, ACPU, 3)
#define HI_MBX_ACPU2HRF_GPU_DVFS        GEN_MBX_SESSION(HPP, ACPU, 4)
#define HI_MBX_ACPU2VMCU0_VFMW          GEN_MBX_SESSION(VMCU0, ACPU, 5)
#define HI_MBX_TCPU2VMCU0_SSM           GEN_MBX_SESSION(VMCU0, TCPU, 6)
#define HI_MBX_ACPU2HRF_CHECK           GEN_MBX_SESSION(HPP, ACPU, 7)
#define HI_MBX_TCPU2HRF_CHECK           GEN_MBX_SESSION(HPP, TCPU, 8)
#define HI_MBX_ACPU2HRF_PMOC            GEN_MBX_SESSION(HPP, ACPU, 9)
#define HI_MBX_TCPU2HRF_PMOC            GEN_MBX_SESSION(HPP, TCPU, 10)
#define HI_MBX_TCPU2VMCU0_SSM_2         GEN_MBX_SESSION(VMCU0, TCPU, 11)

typedef hi_void(*session_callback)(hi_u32 handle, hi_void *data);
hi_s32 hi_tee_mbx_open(hi_u32 session_id);
hi_s32 hi_tee_mbx_register_irq_callback(hi_u32 handle, session_callback func, hi_void *data);
hi_s32 hi_tee_mbx_rx(hi_u32 handle, hi_u8 *msg, hi_u32 msg_len, hi_u32 *rx_len, hi_u32 timeout);
hi_s32 hi_tee_mbx_tx(hi_u32 handle, const hi_u8 *msg, hi_u32 msg_len, hi_u32 *tx_len, hi_u32 timeout);
hi_s32 hi_tee_mbx_close(hi_u32 handle);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cpluscplus */

#endif /* _HI_DRV_MAILBOX_H_ */
