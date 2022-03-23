/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 */
#ifndef __IPC_PLATFORM_H__
#define __IPC_PLATFORM_H__

#include <drv_module.h>
#include <register_ops.h>
#include <sre_typedef.h>
#include <hisi_boot.h>
#include <hisi_debug.h>
#include <osl_balong.h>

#ifdef __cplusplus
extern "C" {
#endif

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI9500 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI9510)
#define HI_IPCM_REGBASE_ADDR 0xE501F000
#define HI_IPCM_REGBASE_SIZE 0x1000
#define INT_LVL_AP2MDM0_IPCM_S 60
#define INT_LVL_AP2MDM1_IPCM_S 61
#endif

#define ipc_print_error(fmt, ...) (uart_printf_func("ipc: %s " fmt, __FUNCTION__, ##__VA_ARGS__))

/* 处理器类型 */
typedef enum tagIPC_INT_CORE_E {
    IPC_CORE_ACORE = 0x0,
    IPC_CORE_CCORE,
    IPC_CORE_MCORE,
    IPC_CORE_NRCCPU = 0x7,
    /* !!!!新增元素请添加到最后，IPC_CORE_BUTTOM前 */
    IPC_CORE_BUTTOM
} IPC_INT_CORE_E;

/* ********************************************************
 * 添加新IPC资源，枚举命名格式:
 * IPC_<目标处理器>_INT_SRC_<源处理器>_<功能/作用>
 * 目标处理器:ACPU、CCPU、MCU 、NRCCPU
 * 源处理器  :ACPU、CCPU、MCU 、NRCCPU
 * 功能/作用 :
 * ******************************************************* */
typedef enum tagIPC_INT_LEV_E {
    /* 安全OS接收的ipc 中断 */
    IPC_SECOS_INT_SRC_CCPU_ICC_IFC = 0,  /* ICC共享通道使用，无任务共享IPC;modem-->安全OS */
    IPC_SECOS_INT_SRC_CCPU_ICC_VSIM = 1, /* 天际通通道使用，无任务私有IPC;modem-->安全OS */

    /* modem接收的 ipc 中断 */
    IPC_CCPU_INT_SRC_SECOS_ICC_IFC = 0,  /* ICC共享通道使用，无任务共享IPC;安全OS-->modem */
    IPC_CCPU_INT_SRC_SECOS_ICC_VSIM = 1, /* 天际通通道使用，无任务私有IPC;安全OS-->modem */

    /* 安全OS接收的nrccpu ipc 中断 */
    IPC_SECOS_INT_SRC_NRCCPU_ICC_IFC = 0,  /* ICC共享通道使用，无任务共享IPC;modem-->安全OS */
    IPC_SECOS_INT_SRC_NRCCPU_ICC_VSIM = 1, /* 天际通通道使用，无任务私有IPC;modem-->安全OS */

    /* nrccpu接收的 ipc 中断 */
    IPC_NRCCPU_INT_SRC_SECOS_ICC_IFC = 0,  /* ICC共享通道使用，无任务共享IPC;安全OS-->modem */
    IPC_NRCCPU_INT_SRC_SECOS_ICC_VSIM = 1, /* 天际通通道使用，无任务私有IPC;安全OS-->modem */

    /* !!!!新增元素请添加到最后，IPC_INT_BUTTOM前 */
    IPC_INT_BUTTOM = 32,
} IPC_INT_LEV_E;

typedef enum tagIPC_SEM_ID_E {
    IPC_SEM_BEGIN = 0,

    /* !!!!新增元素请添加到最后，IPC_SEM_BUTTOM前 */
    IPC_SEM_BUTTOM = 32
} IPC_SEM_ID_E;

int bsp_ipc_int_enable(IPC_INT_LEV_E ulLvl);
int bsp_ipc_int_disable(IPC_INT_LEV_E ulLvl);
int bsp_ipc_int_connect(IPC_INT_LEV_E ulLvl, voidfuncptr routine, u32 parameter);
int bsp_ipc_int_disconnect(IPC_INT_LEV_E ulLvl, voidfuncptr routine, u32 parameter);
int bsp_ipc_int_send(IPC_INT_CORE_E enDstCore, IPC_INT_LEV_E ulLvl);

#ifdef __cplusplus
}
#endif

#endif
