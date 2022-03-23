/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
 * foss@huawei.com
 *
 * If distributed as part of the Linux kernel, the following license terms
 * apply:
 *
 * * This program is free software; you can redistribute it and/or modify
 * * it under the terms of the GNU General Public License version 2 and
 * * only version 2 as published by the Free Software Foundation.
 * *
 * * This program is distributed in the hope that it will be useful,
 * * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * * GNU General Public License for more details.
 * *
 * * You should have received a copy of the GNU General Public License
 * * along with this program; if not, write to the Free Software
 * * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 * Otherwise, the following license terms apply:
 *
 * * Redistribution and use in source and binary forms, with or without
 * * modification, are permitted provided that the following conditions
 * * are met:
 * * 1) Redistributions of source code must retain the above copyright
 * *    notice, this list of conditions and the following disclaimer.
 * * 2) Redistributions in binary form must reproduce the above copyright
 * *    notice, this list of conditions and the following disclaimer in the
 * *    documentation and/or other materials provided with the distribution.
 * * 3) Neither the name of Huawei nor the names of its contributors may
 * *    be used to endorse or promote products derived from this software
 * *    without specific prior written permission.
 *
 * * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __OSL_BALONG_H__
#define __OSL_BALONG_H__

#include <register_ops.h>
#include <sre_task.h>
#include <sre_sys.h>
#include <mem_ops.h>
#include <legacy_mem_ext.h> // SRE_MemAlloc
#include <sre_typedef.h> // UINT32
#include <sre_hwi.h>
#include <secure_gic_common.h>
#include <drv_legacy_def.h> // SEM_HANDLE_T
#include <hisi_boot.h>
#include "tee_log.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define isb() __asm__ __volatile__ ("isb" : : : "memory")
#define dsb() __asm__ __volatile__ ("dsb" : : : "memory")
#define dmb() __asm__ __volatile__ ("dmb" : : : "memory")

#define mb()    dsb()
#define rmb()   dmb()
#define wmb()   mb()

#ifndef BSP_OK
#define BSP_OK              (0)
#endif

#ifndef BSP_ERROR
#define BSP_ERROR           (-1)
#endif

#ifndef true
#define true    1
#endif

#ifndef false
#define false   0
#endif

#ifndef UNUSED
#define UNUSED(a) (a=a)
#endif

typedef void (*voidfuncptr)(u32);

typedef u32 osl_sem_id;

static inline void* osl_malloc(unsigned int nBytes)
{
    return SRE_MemAlloc(0 , 0, nBytes);
}

static inline unsigned int osl_free(void *objp)
{
    return SRE_MemFree(0, objp);
}

static inline unsigned int osl_sem_init(u32 val, osl_sem_id* mutex)
{
    UNUSED(val);
    UNUSED(mutex);
    return SRE_OK;
}

static inline unsigned int osl_sem_up(osl_sem_id* sem)
{
    UNUSED(sem);
    return SRE_OK;
}

static inline unsigned int osl_sem_down(osl_sem_id* sem)
{
    UNUSED(sem);
    return SRE_OK;
}

typedef enum {
    IRQ_NONE,
    IRQ_HANDLED
} irqreturn_t;
typedef irqreturn_t (*irq_handler_t)(void *);

static inline int request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags,
        const char *name, void *arg)
{
    UNUSED(flags);
    UNUSED(name);
    UINT32 ret = SRE_HwiCreate((HWI_HANDLE_T)(irq), 0xa0, INT_SECURE, (HWI_PROC_FUNC)handler, (HWI_ARG_T)(uintptr_t)arg);
    if(ret != SRE_OK)
    {
        tloge("SRE_HwiCreate irq %d errorNO 0x%x\n", irq, ret);
        return ret;
    }
    ret = SRE_HwiEnable((HWI_HANDLE_T)irq);
    if(ret != SRE_OK)
    {
        tloge("SRE_HwiEnable irq %d errorNO 0x%x\n", irq,ret);
        return ret;
    }
    return ret;
}

static inline void free_irq(unsigned int irq, void *arg)
{
    UNUSED(arg);
    UINTPTR ret = SRE_HwiDisable((HWI_HANDLE_T)irq);
    if(ret != SRE_OK)
    {
        tloge("SRE_HwiDisable irq %d errorNO 0x%x\n", irq, ret);
        return;
    }
    ret = SRE_HwiDelete((HWI_HANDLE_T)irq);/* [false alarm]:误报 */
    if(ret != SRE_OK)
    {
        tloge("SRE_HwiDelete irq %d errorNO 0x%x\n", irq, ret);
        return;
    }

}

static inline int disable_irq( unsigned int num )
{
    if(OS_ERRNO_HWI_NUM_INVALID == SRE_HwiDisable((HWI_HANDLE_T)num))
    {
        return BSP_ERROR;
    }
    return BSP_OK;
}


/*此处用于存放任务优先级 ---begin*/
#define  ICC_TASK_PRIVATE_PRI         (4)
/*此处用于存放任务优先级 ---end*/

typedef VOID (* TSK_ENTRY_FUNC)(UINT32 uwParam1,
                                UINT32 uwParam2,
                                UINT32 uwParam3,
                                UINT32 uwParam4);

#define OSL_TASK_FUNC   TSK_ENTRY_FUNC
typedef UINT32          OSL_TASK_ID;


static inline  s32 osl_task_init(
    char *        name,         /* name of new task (stored at pStackBase) */
    int           priority,     /* priority of new task */
    int           stackSize,    /* size (bytes) of stack needed plus name */
    OSL_TASK_FUNC       entryPt,      /* entry point of new task */
    void *para,         /* 1st of 10 req'd args to pass to entryPt */
    OSL_TASK_ID *     tskid
   )
{
    UNUSED(name);
    UNUSED(priority);
    UNUSED(stackSize);
    UNUSED(entryPt);
    UNUSED(para);
    UNUSED(tskid);
    return SRE_OK;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

