/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: mailbox driver in itrustee
 */
#include "mbx_common.h"

hi_s32 hi_tee_mbx_open(hi_u32 session_id)
{
    return mbx_open(session_id, MBX_RX_BUFF_SIZE, MBX_TX_BUFF_SIZE);
}

hi_s32 hi_tee_mbx_close(hi_u32 handle)
{
    return mbx_close(handle);
}

hi_s32 hi_tee_mbx_register_irq_callback(hi_u32 handle, session_callback func, hi_void *data)
{
    return mbx_register_irq_callback(handle, func, data);
}

hi_s32 hi_tee_mbx_rx(hi_u32 handle, hi_u8 *msg, hi_u32 msg_len, hi_u32 *rx_len, hi_u32 timeout)
{
    return mbx_rx(handle, msg, msg_len, rx_len, timeout);
}

hi_s32 hi_tee_mbx_tx(hi_u32 handle, const hi_u8 *msg, hi_u32 msg_len, hi_u32 *tx_len, hi_u32 timeout)
{
    return mbx_tx(handle, msg, msg_len, tx_len, timeout);
}

hi_void mbx_polling_rx(hi_void)
{
#ifndef SUPPORT_MBX_INTERRUPT
    struct mailbox *mailbox;

    mailbox = get_mailbox_data();
    if (mailbox == HI_NULL) {
        return;
    }
    mbx_rx_msg((hi_void *)mailbox->tcpu_vmcu0.rx_head_addr);
    mbx_rx_msg((hi_void *)mailbox->tcpu_hpp.rx_head_addr);
#endif
    return;
}

static hi_void init_vmcu0_reg(struct session *session, struct mailbox *mailbox)
{
    if (session == HI_NULL || mailbox == HI_NULL) {
        return;
    }
    if (mailbox->tcpu_vmcu0.base_addr == HI_NULL) {
        return;
    }
    session->tx_reg = (struct reg *)MBX_MALLOC(sizeof(struct reg));
    if (session->tx_reg == HI_NULL) {
        return;
    }
    session->tx_reg->argv_size = TCPU_TO_VMCU_ARGS_NUM;
    session->tx_reg->version = mailbox->tcpu_vmcu0.base_addr + MAILBOX_VERSION_OFFSET;
    session->tx_reg->head = mailbox->tcpu_vmcu0.base_addr + TCPU_TO_VMCU_HEAD_OFFSET;
    session->tx_reg->argv = mailbox->tcpu_vmcu0.base_addr + TCPU_TO_VMCU_ARGS_OFFSET;
    session->tx_reg->trigger_rx = mailbox->tcpu_vmcu0.base_addr + TCPU_TO_VMCU_SEND_OFFSET;
    session->tx_reg->pending = mailbox->tcpu_vmcu0.base_addr + VMCU_INTR_FROM_TCPU_OFFSET;
    session->tx_reg->lock = &mailbox->tx_vmcu0_lock;

    session->rx_reg = (struct reg *)MBX_MALLOC(sizeof(struct reg));
    if (session->rx_reg == HI_NULL) {
        return;
    }
    session->rx_reg->argv_size = VMCU_TO_TCPU_ARGS_NUM;
    session->rx_reg->version = mailbox->tcpu_vmcu0.base_addr + MAILBOX_VERSION_OFFSET;
    session->rx_reg->head = mailbox->tcpu_vmcu0.base_addr + VMCU_TO_TCPU_HEAD_OFFSET;
    session->rx_reg->argv = mailbox->tcpu_vmcu0.base_addr + VMCU_TO_TCPU_ARGS_OFFSET;
    session->rx_reg->trigger_rx = mailbox->tcpu_vmcu0.base_addr + VMCU_TO_TCPU_SEND_OFFSET;
    session->rx_reg->pending = mailbox->tcpu_vmcu0.base_addr + TCPU_INTR_FROM_VMCU_OFFSET;

    return;
}

static hi_void init_hpp_reg(struct session *session, struct mailbox *mailbox)
{
    if (session == HI_NULL || mailbox == HI_NULL) {
        return;
    }
    if (mailbox->tcpu_hpp.base_addr == HI_NULL) {
        return;
    }
    session->tx_reg = (struct reg *)MBX_MALLOC(sizeof(struct reg));
    if (session->tx_reg == HI_NULL) {
        return;
    }
    session->tx_reg->argv_size = TCPU_TO_HPP_ARGS_NUM;
    session->tx_reg->version = mailbox->tcpu_hpp.base_addr + MAILBOX_VERSION_OFFSET;
    session->tx_reg->head = mailbox->tcpu_hpp.base_addr + TCPU_TO_HPP_HEAD_OFFSET;
    session->tx_reg->argv = mailbox->tcpu_hpp.base_addr + TCPU_TO_HPP_ARGS_OFFSET;
    session->tx_reg->trigger_rx = mailbox->tcpu_hpp.base_addr + TCPU_TO_HPP_SEND_OFFSET;
    session->tx_reg->pending = mailbox->tcpu_hpp.base_addr + HPP_INTR_FROM_TCPU_OFFSET;
    session->tx_reg->lock = &mailbox->tx_hpp_lock;

    session->rx_reg = (struct reg *)MBX_MALLOC(sizeof(struct reg));
    if (session->rx_reg == HI_NULL) {
        return;
    }
    session->rx_reg->argv_size = HPP_TO_TCPU_ARGS_NUM;
    session->rx_reg->version = mailbox->tcpu_hpp.base_addr + MAILBOX_VERSION_OFFSET;
    session->rx_reg->head = mailbox->tcpu_hpp.base_addr + HPP_TO_TCPU_HEAD_OFFSET;
    session->rx_reg->argv = mailbox->tcpu_hpp.base_addr + HPP_TO_TCPU_ARGS_OFFSET;
    session->rx_reg->trigger_rx = mailbox->tcpu_hpp.base_addr + HPP_TO_TCPU_SEND_OFFSET;
    session->rx_reg->pending = mailbox->tcpu_hpp.base_addr + TCPU_INTR_FROM_HPP_OFFSET;

    return;
}

hi_void init_mailbox_reg(struct session *session, hi_u32 session_id, struct mailbox *mailbox)
{
    hi_u32 local_side = mailbox->local_cpu;
    hi_u32 remote_side = SESSION_ID_SIDE0(session_id) == local_side ? \
                         SESSION_ID_SIDE1(session_id) : SESSION_ID_SIDE0(session_id);

    if (local_side != SESSION_ID_SIDE0(session_id) && \
            local_side != SESSION_ID_SIDE1(session_id)) {
        return;
    }
    if (session == HI_NULL) {
        return;
    }
    switch (local_side) {
        case TCPU:
            if (remote_side == VMCU0) {
                init_vmcu0_reg(session, mailbox);
            } else if (remote_side == HPP) {
                init_hpp_reg(session, mailbox);
            } else {
                session->tx_reg = HI_NULL;
                session->rx_reg = HI_NULL;
            }
            break;

        default:
            session->tx_reg = HI_NULL;
            session->rx_reg = HI_NULL;
            break;
    }

    return;
}

#ifdef SUPPORT_MBX_INTERRUPT
static MBX_IRQ_RET mailbox_vmcu0_irq_handler(void)
{
    hi_s32 ret;
    struct mailbox *mailbox;

    mailbox = get_mailbox_data();
    if (mailbox == HI_NULL) {
        return;
    }
    ret = mbx_rx_msg((hi_void *)mailbox->tcpu_vmcu0.rx_head_addr);
    if (ret != HI_MBX_SUCCESS) {
        MBX_WRITEL(0x00, mailbox->tcpu_vmcu0.base_addr + TCPU_INTR_FROM_VMCU_OFFSET);
        MBX_ERR_PRINT("mbx_rx_msg vmcu0 error and ret:0x%x\n", ret);
    }

    return MBX_IRQ_HANDLED;
}

static MBX_IRQ_RET mailbox_hpp_irq_handler(void)
{
    hi_s32 ret;
    struct mailbox *mailbox;

    mailbox = get_mailbox_data();
    if (mailbox == HI_NULL) {
        return;
    }
    ret = mbx_rx_msg((hi_void *)mailbox->tcpu_hpp.rx_head_addr);
    if (ret != HI_MBX_SUCCESS) {
        MBX_WRITEL(0x00, mailbox->tcpu_hpp.base_addr + TCPU_INTR_FROM_HPP_OFFSET);
        MBX_ERR_PRINT("mbx_rx_msg hpp error and ret:0x%x\n", ret);
    }

    return MBX_IRQ_HANDLED;
}
#endif

hi_s32 mailbox_init(enum cpu_id local_cpu)
{
    struct mailbox *mailbox;
#ifdef SUPPORT_MBX_INTERRUPT
    hi_s32 ret;
#endif

    mailbox = get_mailbox_data();
    if ((mailbox == HI_NULL) || (local_cpu >= CPU_MAX)) {
        return HI_ERR_MAILBOX_NOT_SUPPORT;
    }
    if (mailbox->initalized != HI_FALSE) {
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    MBX_INIT_LIST_HEAD(&mailbox->list_head);
    mailbox->local_cpu = local_cpu;
    MBX_MUTEX_INIT(&mailbox->list_lock);
    MBX_MUTEX_INIT(&mailbox->tx_vmcu0_lock);
    MBX_MUTEX_INIT(&mailbox->tx_hpp_lock);
    MBX_MUTEX_INIT(&mailbox->tx_tpp_lock);

    mailbox->tcpu_vmcu0.base_addr = (hi_u32 *)MBX_TCPU_VMCU0_BASE_ADDR;
    mailbox->tcpu_vmcu1.base_addr = (hi_u32 *)MBX_TCPU_VMCU1_BASE_ADDR;
    mailbox->tcpu_hpp.base_addr = (hi_u32 *)MBX_TCPU_HPP_BASE_ADDRESS;
    if ((mailbox->tcpu_vmcu0.base_addr == HI_NULL) || (mailbox->tcpu_vmcu1.base_addr == HI_NULL) ||
        (mailbox->tcpu_hpp.base_addr == HI_NULL)) {
        return HI_ERR_MAILBOX_NO_MEMORY;
    }

    mailbox->tcpu_vmcu0.rx_head_addr = mailbox->tcpu_vmcu0.base_addr + VMCU_TO_TCPU_HEAD_OFFSET;
    mailbox->tcpu_vmcu1.rx_head_addr = mailbox->tcpu_vmcu1.base_addr + VMCU_TO_TCPU_HEAD_OFFSET;
    mailbox->tcpu_hpp.rx_head_addr = mailbox->tcpu_hpp.base_addr + HPP_TO_TCPU_HEAD_OFFSET;
    mailbox->initalized = HI_TRUE;
#ifdef SUPPORT_MBX_INTERRUPT
    ret = hi_tee_drv_hal_request_irq(MBX_IRQ_VMCU2TCPU, (void *)mailbox_vmcu0_irq_handler, 0, mailbox);
    if (ret != 0) {
        MBX_ERR_PRINT("Request MBX_IRQ_VMCU2TCPU IRQ failed\n");
        mailbox->tcpu_vmcu0.base_addr = HI_NULL;
        mailbox->tcpu_vmcu1.base_addr = HI_NULL;
        mailbox->tcpu_hpp.base_addr = HI_NULL;
        mailbox->initalized = HI_FALSE;
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    ret = hi_tee_drv_hal_request_irq(MBX_IRQ_HPP2TCPU, (void *)mailbox_hpp_irq_handler, 0, mailbox);
    if (ret != 0) {
        MBX_ERR_PRINT("Request MBX_IRQ_HPP2TCPU IRQ failed\n");
        mailbox->tcpu_vmcu0.base_addr = HI_NULL;
        mailbox->tcpu_vmcu1.base_addr = HI_NULL;
        mailbox->tcpu_hpp.base_addr = HI_NULL;
        mailbox->initalized = HI_FALSE;
        return HI_ERR_MAILBOX_NOT_INIT;
    }
#endif

    return HI_MBX_SUCCESS;
}

hi_s32 mailbox_deinit(hi_void)
{
    struct mailbox *mailbox;

    mailbox = get_mailbox_data();
    if (mailbox == HI_NULL) {
        return HI_ERR_MAILBOX_NOT_SUPPORT;
    }
    mailbox->initalized = HI_FALSE;
    mailbox->local_cpu = 0;
#ifdef SUPPORT_MBX_INTERRUPT
    hi_tee_drv_hal_unregister_irq(MBX_IRQ_VMCU2TCPU);
#endif

    return HI_MBX_SUCCESS;
}

static hi_s32 mailbox_mod_init(hi_void)
{
    int ret;

    ret = mailbox_init(TCPU);
    if (ret < 0) {
        MBX_ERR_PRINT("drv_mailbox_init 0x%x failed\n", ret);
        return ret;
    }

    return 0;
}

hi_tee_drv_hal_driver_init(mailbox, 0, mailbox_mod_init, HI_NULL, HI_NULL, HI_NULL);
