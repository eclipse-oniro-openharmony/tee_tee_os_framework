/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: sample for mailbox in secure OS
 */
#include "hi_tee_mbx.h"
#include "mbx_common.h"

#define MBX_RET_ACPU_CMD      0x5A
#define MBX_TX_TEE_CMD        0x69
#define MBX_TX_TPP_CMD        0x47
#define MBX_DEFAULT_HANDLE    0xFFFFFFFF
#define MBX_DEFAULT_TIMEOUT   0x500

void mailbox_callback(hi_u32 handle, void *data)
{
    hi_u8 buf[MBX_RX_BUFF_SIZE];
    hi_s32 ret;
    hi_u32 rx_len;
    hi_u32 tx_len;

    ret = hi_tee_mbx_rx(handle, buf, MBX_RX_BUFF_SIZE, &rx_len, MBX_DEFAULT_TIMEOUT);
    if (ret < 0) {
        MBX_ERR_PRINT("drv_mbx_rx in callback failed, ret:0x%x\n", ret);
        return;
    }
    if (rx_len == 0) {
        MBX_ERR_PRINT("drv_mbx_rx get nothing!\n");
        return;
    }
    if (buf[0] == MBX_TX_TEE_CMD) {
        buf[0] = MBX_RET_ACPU_CMD;
        ret = hi_tee_mbx_tx(handle, buf, rx_len, &tx_len, MBX_DEFAULT_TIMEOUT);
        if ((ret < 0) || (tx_len != rx_len)) {
            MBX_ERR_PRINT("drv_mbx_tx failed, ret:0x%x\n", ret);
            return;
        }
    }

    return;
}

void sample_mailbox(void)
{
    hi_s32 ret;
    hi_u32 handle_pmoc;
    hi_u32 handle_ssm;

    ret = hi_tee_mbx_open(HI_MBX_TCPU2HRF_PMOC);
    if (ret < 0) {
        MBX_ERR_PRINT("mailbox_open HI_MBX_ACPU2HRF_PMOC failed, ret:0x%x\n", ret);
        return;
    }
    handle_pmoc = ret;
    ret = hi_tee_mbx_register_irq_callback(handle_pmoc, mailbox_callback, HI_NULL);
    if (ret < 0) {
        MBX_ERR_PRINT("drv_mbx_register_irq_callback failed, ret:0x%x\n", ret);
        return;
    }
    ret = hi_tee_mbx_open(HI_MBX_TCPU2VMCU0_SSM);
    if (ret < 0) {
        MBX_ERR_PRINT("mailbox_open HI_MBX_TCPU2VMCU0_SSM failed, ret:0x%x\n", ret);
        return;
    }
    handle_ssm = ret;
    ret = hi_tee_mbx_register_irq_callback(handle_ssm, mailbox_callback, HI_NULL);
    if (ret < 0) {
        MBX_ERR_PRINT("drv_mbx_register_irq_callback failed, ret:0x%x\n", ret);
        return;
    }
}

