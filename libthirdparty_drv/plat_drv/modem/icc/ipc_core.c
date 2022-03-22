/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * foss@huawei.com
 *
 */
#include <sre_hwi.h>
#include <secure_gic_common.h>
#include <drv_module.h>
#include <sre_typedef.h> // UINT32
#include "platform.h"
#include <securec.h>
#include "ipc_core.h"

struct ipc_control g_ipc_ctrl;
struct ipc_debug_s g_ipc_debug = { 0 };

extern void irq_lock();
extern void irq_unlock();


/*lint -save -e732 */
/* ****************************************************************************
* 函 数 名  :  bsp_ipc_int_enable
*
* 功能描述  :  使能IPC中断
*
* 输入参数  :  ulLvl :中断bit位

* 输出参数  :  无
*
* 返 回 值  :  无
*
* 修改记录  :
**************************************************************************** */
int bsp_ipc_int_enable(IPC_INT_LEV_E ulLvl)
{
    unsigned int u32IntMask;

    if (ulLvl >= IPC_INT_BUTTOM) {
        ipc_print_error("[%s]Wrong param , line:%d,param = %d\n", __FUNCTION__, __LINE__, ulLvl);
        return BSP_ERROR;
    }

    /* 写中断屏蔽寄存器 */
    irq_lock();
    u32IntMask = readl(g_ipc_ctrl.ipc_base + BSP_IPC_CPU_INT_MASK(g_ipc_ctrl.core_num));
    u32IntMask |= (u32)1 << (u32)ulLvl;
    writel(u32IntMask, g_ipc_ctrl.ipc_base + BSP_IPC_CPU_INT_MASK(g_ipc_ctrl.core_num));
    irq_unlock();

    return BSP_OK;
}

/* ****************************************************************************
* 函 数 名  :  bsp_ipc_int_disable
*
* 功能描述  :  去使能IPC中断
*
* 输入参数  :  ulLvl :中断bit位

* 输出参数  :  无
*
* 返 回 值  :  无
*
* 修改记录  :
**************************************************************************** */
int bsp_ipc_int_disable(IPC_INT_LEV_E ulLvl)
{
    unsigned int u32IntMask;

    if (ulLvl >= IPC_INT_BUTTOM) {
        ipc_print_error("[%s]Wrong param , line:%d,param = %d\n", __FUNCTION__, __LINE__, ulLvl);
        return BSP_ERROR;
    }

    /* 写中断屏蔽寄存器 */
    irq_lock();
    u32IntMask = readl(g_ipc_ctrl.ipc_base + BSP_IPC_CPU_INT_MASK(g_ipc_ctrl.core_num));
    u32IntMask = u32IntMask & (~((u32)1 << (u32)ulLvl));
    writel(u32IntMask, g_ipc_ctrl.ipc_base + BSP_IPC_CPU_INT_MASK(g_ipc_ctrl.core_num));
    irq_unlock();

    return BSP_OK;
}

/* ****************************************************************************
* 函 数 名  :  bsp_ipc_int_connect
*
* 功能描述  :  挂接IPC中断
*
* 输入参数  :  ulLvl :中断bit位；routine :中断回调函数；parameter :入参

* 输出参数  :  无
*
* 返 回 值  :  无
*
* 修改记录  :
**************************************************************************** */
s32 bsp_ipc_int_connect(IPC_INT_LEV_E ulLvl, voidfuncptr routine, u32 parameter)
{
    if (ulLvl >= IPC_INT_BUTTOM) {
        ipc_print_error("[%s]Wrong param , line:%d,param = %d\n", __FUNCTION__, __LINE__, ulLvl);
        return BSP_ERROR;
    }

    irq_lock();
    g_ipc_ctrl.ipc_int_table[ulLvl].routine = routine;
    g_ipc_ctrl.ipc_int_table[ulLvl].arg = parameter;
    irq_unlock();

    return BSP_OK;
}

/* ****************************************************************************
* 函 数 名  :  bsp_ipc_int_disconnect
*
* 功能描述  :  去挂接IPC中断
*
* 输入参数  :  ulLvl :中断bit位；routine :中断回调函数；parameter :入参

* 输出参数  :  无
*
* 返 回 值  :  无
*
* 修改记录  :
**************************************************************************** */
int bsp_ipc_int_disconnect(IPC_INT_LEV_E ulLvl, voidfuncptr routine, u32 parameter)
{
    UNUSED(routine);
    UNUSED(parameter);

    if (ulLvl >= IPC_INT_BUTTOM) {
        ipc_print_error("[%s]Wrong param , line:%d,param = %d\n", __FUNCTION__, __LINE__, ulLvl);
        return BSP_ERROR;
    }

    irq_lock();
    g_ipc_ctrl.ipc_int_table[ulLvl].routine = NULL;
    g_ipc_ctrl.ipc_int_table[ulLvl].arg = 0;
    irq_unlock();

    return BSP_OK;
} /*lint !e715*/

/* ****************************************************************************
* 函 数 名  :  ipc_int_handler
*
* 功能描述  :  IPC中断处理函数
*
* 输入参数  :  arg :入参

* 输出参数  :  无
*
* 返 回 值  :  无
*
* 修改记录  :
**************************************************************************** */
irqreturn_t ipc_int_handler(void *arg)
{
    unsigned int i;
    unsigned int u32IntStat;
    unsigned int u32Date = 0x1;
    unsigned int u32BitValue;

    UNUSED(arg);

    u32IntStat = readl(g_ipc_ctrl.ipc_base + BSP_IPC_CPU_INT_STAT(g_ipc_ctrl.core_num));

    /* 清中断 */
    writel(u32IntStat, g_ipc_ctrl.ipc_base + BSP_IPC_CPU_INT_CLR(g_ipc_ctrl.core_num));

    /* 遍历32个中断 */
    for (i = 0; i < INTSRC_NUM; i++) {
        if (i != 0) {
            u32Date <<= 1;
        }
        u32BitValue = u32IntStat & u32Date;

        /* 如果有中断 ,则调用对应中断处理函数 */
        if (u32BitValue != 0) {
            /* 调用注册的中断处理函数 */
            if (g_ipc_ctrl.ipc_int_table[i].routine != NULL) {
                g_ipc_ctrl.last_int_cb_addr = (uintptr_t)(g_ipc_ctrl.ipc_int_table[i].routine);
                g_ipc_ctrl.ipc_int_table[i].routine(g_ipc_ctrl.ipc_int_table[i].arg);
            } else {
                ipc_print_error("BSP_DRV_IpcIntHandler:No IntConnect,BSP_ERROR!.int num =%d\n", i);
            }
            g_ipc_debug.u32IntHandleTimes[i]++;
        }
    }

    return IRQ_HANDLED;
} /*lint !e715*/

/* ****************************************************************************
* 函 数 名  :  bsp_ipc_int_send
*
* 功能描述  :  发送IPC中断
*
* 输入参数  :  enDstCore :目标核；ulLvl :中断号

* 输出参数  :  无
*
* 返 回 值  :  无
*
* 修改记录  :
**************************************************************************** */
int bsp_ipc_int_send(IPC_INT_CORE_E enDstCore, IPC_INT_LEV_E ulLvl)
{
    if (ulLvl >= IPC_INT_BUTTOM) {
        ipc_print_error("[%s]Wrong param , line:%d,param = %d\n", __FUNCTION__, __LINE__, ulLvl);
        return BSP_ERROR;
    }
    if (enDstCore >= IPC_CORE_BUTTOM) {
        ipc_print_error("[%s]Wrong param , line:%d,param = %d\n", __FUNCTION__, __LINE__, enDstCore);
        return BSP_ERROR;
    }

    /* 写原始中断寄存器,产生中断 */
    irq_lock();
    writel((u32)1 << (u32)ulLvl, g_ipc_ctrl.ipc_base + BSP_IPC_CPU_RAW_INT(enDstCore));
    irq_unlock();

    g_ipc_debug.u32RecvIntCore = enDstCore;
    g_ipc_debug.u32IntSendTimes[enDstCore][ulLvl]++;

    return BSP_OK;
}
/*lint -restore +e732 */

/* ****************************************************************************
* 函 数 名  :  bsp_ipc_init
*
* 功能描述  :  IPC初始化函数
*
* 输入参数  :  无

* 输出参数  :  无
*
* 返 回 值  :  无
*
* 修改记录  :
**************************************************************************** */
int bsp_ipc_init(void)
{
    int ret, i;

    g_ipc_ctrl.core_num = IPC_CORE_ACORE;

    for (i = 0; i < INTSRC_NUM; i++) {
        g_ipc_ctrl.sem_exist[i] = false;
    }

    g_ipc_ctrl.ipc_base = HI_IPCM_REGBASE_ADDR_VIRT;

    writel(0x0, g_ipc_ctrl.ipc_base + BSP_IPC_CPU_INT_MASK(g_ipc_ctrl.core_num));
    writel(0x0, g_ipc_ctrl.ipc_base + BSP_IPC_SEM_INT_MASK(g_ipc_ctrl.core_num));
    writel(0xffffffff, g_ipc_ctrl.ipc_base + BSP_IPC_CPU_INT_CLR(g_ipc_ctrl.core_num)); /* 清所有32个中断 */

    ret = request_irq(INT_LVL_AP2MDM0_IPCM_S, (irq_handler_t)ipc_int_handler, 0, "ipc_irq", (void *)NULL); // IPC_INT
    if (ret) {
        ipc_print_error("ipc int handler error,init failed\n");
        return -1;
    }


    return 0;
}

int bsp_ipc_resume(void)
{
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 ||  \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
    /* modem IPC */
    const HWI_HANDLE_T irq = INT_LVL_AP2MDM0_IPCM_S;
    UINT32 ret;

    ret = SRE_HwiResume(irq, 0, INT_SECURE);
    if (ret) {
        ipc_print_error("SRE_HwiResume modem IPC irq %u failed, error %d\n", irq, ret);
        return -1;
    }

    ret = SRE_HwiEnable(irq);
    if (ret) {
        ipc_print_error("SRE_HwiEnable modem IPC irq %u failed, error %d\n", irq, ret);
        return -1;
    }

    /*
     * GIC has already been re-initialized by kernel,
     * so no need to invoke GIC_secure_cpuInterface_ctrl_init();
     */

    return 0;
#else
    return 0;
#endif
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_BALTIMORE && TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(ipc_driver, 0, 0, 0, TC_DRV_MODULE_INIT, bsp_ipc_init, NULL, NULL, NULL, bsp_ipc_resume);
/*lint -e528 +esym(528,*)*/
#endif
