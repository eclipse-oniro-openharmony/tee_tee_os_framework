/******************************************************************************
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
* Description: mailbox driver for itrustee
******************************************************************************/
#ifndef _DRV_MAILBOX_H_
#define _DRV_MAILBOX_H_

#include "hi_log.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_errno.h"
#include "hi_tee_mbx.h"
#include "hi_list.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define SUPPORT_MBX_INTERRUPT
#define MBX_TCPU_VMCU0_BASE_ADDR       0x0129b000
#define MBX_TCPU_VMCU1_BASE_ADDR       0x012bb000
#define MBX_TCPU_HPP_BASE_ADDRESS      0x00B61000

#define MAILBOX_VERSION_OFFSET         0x0
/* tcpu to vmcu0 */
#define TCPU_TO_VMCU_HEAD_OFFSET       (0x0200 / 4)
#define TCPU_TO_VMCU_ARGS_OFFSET       (0x0240 / 4)
#define TCPU_TO_VMCU_ARGS_NUM          (16 * 4)
#define TCPU_TO_VMCU_SEND_OFFSET       (0x0404 / 4)
#define TCPU_INTR_FROM_VMCU_OFFSET     (0x041C / 4)
/* vmcu0 to tcpu */
#define VMCU_TO_TCPU_HEAD_OFFSET       (0x0300 / 4)
#define VMCU_TO_TCPU_ARGS_OFFSET       (0x0310 / 4)
#define VMCU_TO_TCPU_ARGS_NUM          (4 * 4)
#define VMCU_TO_TCPU_SEND_OFFSET       (0x0414 / 4)
#define VMCU_INTR_FROM_TCPU_OFFSET     (0x040C / 4)
#define MBX_IRQ_VMCU2TCPU              (129 + 32)
#define VMCU2TCPU_IRQ_NAME             "int_vmcumbx0_tee"

/* tcpu to hpp */
#define TCPU_TO_HPP_HEAD_OFFSET        (0x0200 / 4)
#define TCPU_TO_HPP_ARGS_OFFSET        (0x0240 / 4)
#define TCPU_TO_HPP_ARGS_NUM           (8 * 4)
#define TCPU_TO_HPP_SEND_OFFSET        (0x0404 / 4)
#define TCPU_INTR_FROM_HPP_OFFSET      (0x041C / 4)
/* hpp to tcpu */
#define HPP_TO_TCPU_HEAD_OFFSET        (0x0300 / 4)
#define HPP_TO_TCPU_ARGS_OFFSET        (0x0310 / 4)
#define HPP_TO_TCPU_ARGS_NUM           (4 * 4)
#define HPP_TO_TCPU_SEND_OFFSET        (0x0414 / 4)
#define HPP_INTR_FROM_TCPU_OFFSET      (0x040C / 4)
#define MBX_IRQ_HPP2TCPU               (163 + 32)
#define HPP2TCPU_IRQ_NAME              "int_hppmbx0_tee"

#define HI_MBX_SUCCESS                  HI_SUCCESS
#define HI_MBX_FAILURE                  HI_FAILURE
#define MBX_DELAY_TIME                  10
#define MBX_RX_BUFF_SIZE                4100
#define MBX_TX_BUFF_SIZE                0
#define SESSION_BUSY                    (1 << 0)
#define SESSION_ID_SIDE0(session_id)    (((session_id) >> 4) & 0xF)
#define SESSION_ID_SIDE1(session_id)    ((session_id) & 0xF)
#define SESSION_ID_NUM(session_id)      (((session_id) >> 8) & 0xFF)
#define SESSION_ID_PORT(session_id)     (((session_id) >> 16) & 0x7F)
#define SESSION_ID_HANDLE(session_id)   (((session_id) >> 8) & 0x7FFF)
#define GEN_SESSION_HANDLE(num, port)   (((num) & 0xFF)  | ((port) & 0x7F) << 8)
#define SESSION_HANDLE_NUM(handle)      ((handle) & 0xFF)
#define SESSION_HANDLE_PORT(handle)     (((handle) >> 8) & 0x7F)

struct buffer {
    hi_u8 *addr;
    hi_u32 size;
    hi_u32 rd_idx;
    hi_u32 wr_idx;
};

struct reg {
    hi_u32 *version;
    hi_u32 *head;
    hi_u32 *argv;
    hi_u32 argv_size;
    hi_u32 *trigger_rx;
    hi_u32 *pending;
    struct hi_tee_hal_mutex *lock;
};

struct session {
    hi_u32 num;
    hi_u32 port;
    hi_s32 rx_status;
    hi_s32 tx_status;
    struct buffer rx_buf;
    struct buffer tx_buf;
    struct reg *rx_reg;
    struct reg *tx_reg;
    session_callback func;
    hi_void *data;
    struct list_head node;
};

union msg_head {
    struct {
        hi_u32 reserved         : 9;  /* [8:0]   */
        hi_u32 port             : 7;  /* [15:9]  */
        hi_u32 num              : 8;  /* [23:16] */
        hi_u32 msg_len          : 7;  /* [30:24] */
        hi_u32 ongoing          : 1;  /* [31]    */
    } bits;
    hi_u32 head;
};

struct addr_info {
    hi_u32 *base_addr;
    hi_u32 *rx_head_addr;
};

struct mailbox {
    enum cpu_id local_cpu;
    hi_u32 initalized;
    struct hi_tee_hal_mutex list_lock;
    struct list_head list_head;
    struct addr_info tcpu_vmcu0;
    struct addr_info tcpu_vmcu1;
    struct addr_info tcpu_hpp;
    struct hi_tee_hal_mutex tx_vmcu0_lock;
    struct hi_tee_hal_mutex tx_hpp_lock;
    struct hi_tee_hal_mutex tx_tpp_lock;
};

inline void mutex_lock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_lock(lock);
    return;
}

inline void mutex_unlock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_unlock(lock);
    return;
}

#define MBX_ERR_PRINT           hi_tee_drv_hal_printf
#define MBX_WARN_PRINT          hi_tee_drv_hal_printf
#define MBX_INFO_PRINT          hi_tee_drv_hal_printf
#define MBX_DBG_PRINT           hi_tee_drv_hal_printf
#define MBX_WRITEL(val, addr)   (*(volatile hi_u32 *)(addr) = (val))
#define MBX_READL(addr)         (*(volatile hi_u32 *)(addr))
#define MBX_LIST_FOR_EACH_ENTRY list_for_each_entry_safe
#define MBX_UDELAY              hi_tee_drv_hal_udelay
#define MBX_MSLEEP              hi_tee_drv_hal_msleep
#define MBX_MALLOC              hi_tee_drv_hal_malloc
#define MBX_FREE                hi_tee_drv_hal_free
#define MBX_MUTEX_INIT(lock)    hi_tee_drv_hal_mutex_init("mailbox", lock)
#define MBX_LIST_ADD            list_add
#define MBX_LIST_DEL            list_del
#define MBX_INIT_LIST_HEAD      INIT_LIST_HEAD
#define MBX_IRQ_RET             hi_void
#define MBX_IRQ_HANDLED

hi_void init_mailbox_reg(struct session *session, hi_u32 session_id, struct mailbox *mailbox);
hi_void mbx_polling_rx(hi_void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _DRV_MAILBOX_H_ */
