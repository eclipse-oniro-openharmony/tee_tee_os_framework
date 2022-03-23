/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 */

#ifndef _IPC_CORE_H__
#define _IPC_CORE_H__

#include "ipc_platform.h"

#ifdef __cplusplus
extern "C" {
#endif
#define INTSRC_NUM 32

typedef void (*voidfuncptr)(u32);
struct ipc_entry {
    voidfuncptr routine;
    u32 arg;
};

#define HI_IPCM_REGBASE_ADDR_VIRT HI_IPCM_REGBASE_ADDR

#define BSP_IPC_CPU_RAW_INT(i) (0x400 + ((i) * 0x10))
#define BSP_IPC_CPU_INT_MASK(i) (0x404 + ((i) * 0x10))
#define BSP_IPC_CPU_INT_STAT(i) (0x408 + ((i) * 0x10))
#define BSP_IPC_CPU_INT_CLR(i) (0x40C + ((i) * 0x10))

#define BSP_IPC_SEM_RAW_INT(i) (0x600 + ((i) * 0x10))
#define BSP_IPC_SEM_INT_MASK(i) (0x604 + ((i) * 0x10))
#define BSP_IPC_SEM_INT_STAT(i) (0x608 + ((i) * 0x10))
#define BSP_IPC_SEM_INT_CLR(i) (0x60C + ((i) * 0x10))

#define BSP_IPC_HS_CTRL(i, j) (0x800 + ((i) * 0x100) + ((j) * 0x8))
#define BSP_IPC_HS_STAT(i, j) (0x804 + ((i) * 0x100) + ((j) * 0x8))

struct ipc_debug_s {
    u32 u32RecvIntCore;                               /* 当前发送中断目标核ID */
    u32 u32IntHandleTimes[INTSRC_NUM];                /* 记录某号中断接收次数 */
    u32 u32IntSendTimes[IPC_CORE_BUTTOM][INTSRC_NUM]; /* 记录往每个核发送每个中断的次数 */
    u32 u32SemId;                                     /* 当前占用信号量 */
    u32 u32SemTakeTimes[INTSRC_NUM];                  /* 某信号量占用成功次数 */
    u32 u32SemTakeFailTimes[INTSRC_NUM];              /* 某信号量占用失败次数 */
    u32 u32SemGiveTimes[INTSRC_NUM];                  /* 某信号量释放次数 */
    u32 u32IntTimeDelta[INTSRC_NUM];                  /* 记录每个中断对应处理函数所用时间 */
};
struct ipc_control {
    u32 core_num;                               /* 记录IPC模块工作所在的核ID */
    u32 ipc_base;                               /* ipc基址 */
    bool sem_exist[INTSRC_NUM];                 /* 记录信号量是否已经创建 */
    struct ipc_entry ipc_int_table[INTSRC_NUM]; /* 记录每一个中断源注册的回调函数 */
    u32 lock;
    unsigned long last_int_cb_addr; /* 最后一个被回调的中断函数的地址 */
};

#ifdef __cplusplus
}
#endif

#endif /* end #define _IPC_BALONG_H_ */
