/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * foss@huawei.com
 *
 */
#ifndef ICC_PLATFORM_H
#define ICC_PLATFORM_H

#include <securec.h>
#include <sre_typedef.h>
#include <hisi_debug.h>
#include <osl_balong.h>
#include <bsp_icc.h>
#include "ipc_platform.h"


#ifdef __cplusplus
extern "C" {
#endif

#define ICC_CHANNELS_OTHER_CFG 1

#ifndef BSP_ERR_ICC_BASE
#define BSP_ERR_ICC_BASE (int)(0x80000000 | 0x10180000)
#endif

/* C核发生复位 */
#ifndef BSP_ERR_ICC_CCORE_RESETTING
#define BSP_ERR_ICC_CCORE_RESETTING (BSP_ERR_ICC_BASE + 0x12)
#endif

/* 通道满 */
#ifndef ICC_INVALID_NO_FIFO_SPACE
#define ICC_INVALID_NO_FIFO_SPACE (BSP_ERR_ICC_BASE + 0x13)
#endif

/* icc循环buffer错误 */
#ifndef DRV_ERRNO_ICC_RING_BUFFER
#define DRV_ERRNO_ICC_RING_BUFFER 0x1010
#endif

#define ICC_THIS_CPU (ICC_CPU_APP)
#define ICC_SEND_CPU (ICC_CPU_MODEM)
#define ICC_RECV_IPC_SHARED (IPC_SECOS_INT_SRC_CCPU_ICC_IFC)
#define ICC_TASK_STK_SIZE 0x1000
#define NOTIFY_STOP_MASK 0x8000

#define ICC_SHAREDTASK_SHAREDIPC_IDX 0xfffffffe
#define ICC_NOTASK_SHAREDIPC_IDX 0xfffffffe

#define SHM_S_ADDR_ICC (g_icc_channel_base.addr)
#define SHM_S_SIZE_ICC (g_icc_channel_base.size)

#define SRAM_ADDR_ICC SHM_S_ADDR_ICC
#define SRAM_SIZE_ICC SHM_S_SIZE_ICC

#define ICC_DBG_MSG_LEN_IN_DDR 0x20
#define ICC_DBG_MSG_ADDR_IN_DDR ((SHM_S_ADDR_ICC + 3) & ~3)
#define ICC_DBG_MSG_LEN_IN_DDR_S 0x20
#define ICC_DBG_MSG_ADDR_IN_DDR_S ((SHM_S_ADDR_ICC + 3) & ~3)

#define ICC_SDDR_S_START_ADDR_ON_THIS_CORE (ICC_DBG_MSG_ADDR_IN_DDR_S + ICC_DBG_MSG_LEN_IN_DDR_S)

#define icc_print_error(fmt, ...) (uart_printf_func("icc: %s " fmt, __FUNCTION__, ##__VA_ARGS__))
#define icc_print_info uart_printf_func
#define icc_print_notice(fmt, ...)
#define icc_print_debug(fmt, ...) do {                                         \
        if (g_icc_dbg.msg_print_sw)              \
            icc_print_error(fmt, ##__VA_ARGS__); \
    } while (0)

typedef u32 icc_task_id;
typedef u32 spinlock_t;
typedef int (*FUNCPTR_1)(int);

struct icc_channel_base {
    unsigned int addr;
    unsigned int size;
};

extern struct icc_channel_base g_icc_channel_base;

/* 数据类型定义start */
struct icc_pm_debug {
    FUNCPTR_1 debug_routine;
    int para;
};

struct icc_channel_vector {
    read_cb_func read_cb;   /* 接收向量的读回调函数指针 */
    void *read_context;     /* 接收向量的读回调函数context */
    write_cb_func write_cb; /* 接收向量的写回调函数指针 */
    void *write_context;    /* 接收向量的写回调函数context */
    struct icc_pm_debug pm_debug;
};

struct wake_lock {
    int lock;
};
#define WAKE_LOCK_SUSPEND 0

struct icc_control {
    u32 cpu_id;                 /* 当前核cpu id */
    u32 state;                  /* icc控制结构体状态: 可用|不可用 */
    icc_task_id shared_task_id; /* 通道共享任务id */
    u32 shared_recv_ipc_irq_id; /* 通道共享的接收数据使用ipc中断 */
    osl_sem_id shared_task_sem; /* 唤醒通道共享任务的信号量 */
    u32 wake_up_flag;
    u32 sleep_flag;
    struct icc_channel *channels[ICC_CHN_ID_MAX]; /* icc_channel的结构体指针数组 */
    u32 channel_size;                             /* 通道数目 */
    struct wake_lock wake_lock;
};

static inline void icc_wake_lock_init(struct wake_lock *lock, int lock_id, const char *name)
{
    UNUSED(lock);
    UNUSED(lock_id);
    UNUSED(name);
    return;
}
static inline void icc_wake_lock(struct wake_lock *lock)
{
    UNUSED(lock);
    return;
}
static inline void icc_wake_unlock(struct wake_lock *lock)
{
    UNUSED(lock);
    return;
}
int icc_channels_init(void);
static inline int icc_pm_init(void)
{
    return ICC_OK;
}
int icc_ccore_is_reseting(u32 cpuid);

void icc_packet_print(struct icc_channel_packet *packet);
int icc_channel_packet_dump(struct icc_channel_packet *packet);
u32 bsp_icc_channel_status_get(u32 real_channel_id, u32 *channel_stat);

void icc_debug_in_isr(void);
s32 icc_debug_init(u32 channel_num);
void icc_debug_before_send(struct icc_channel_packet *packet);
void icc_debug_after_send(struct icc_channel *channel, struct icc_channel_packet *packet, u8 *data);
void icc_debug_before_recv(struct icc_channel_packet *pkg_header);
void icc_debug_in_read_cb(u32 channel_id, u8 *buf, u32 buf_len, u32 read_ptr, u32 write_ptr);
void icc_debug_after_recv(struct icc_channel_packet *pkg_header);

s32 bsp_icc_init(void);
s32 bsp_icc_event_register(u32 channel_id, read_cb_func read_cb, void *read_context, write_cb_func write_cb,
    void *write_context);
s32 bsp_icc_send(u32 cpuid, u32 channel_id, u8 *data, u32 data_len);
s32 bsp_icc_read(u32 channel_id, u8 *buf, u32 buf_len);

#ifdef __cplusplus
}
#endif

#endif
