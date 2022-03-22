/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#ifndef _EICC_PLATFORM_H
#define _EICC_PLATFORM_H

#include <drv_module.h>
#include <sre_hwi.h>

#include <osl_balong.h>
#include <osl_list.h>
#include <bsp_modem_call.h>
#include <bsp_eicc.h>
#include <securec.h>
#include "bsp_shared_ddr.h"

#ifdef __cplusplus
extern "C" {
#endif
#define EICC_FEATURE_PM_EMPTYCHECK 1
#define EICC_FEATURE_PM_ROLLBACK 1
#define EICC_FEATURE_PM_IRQSCTRL 1
#define EICC_FEATURE_DUMP_SUPPORT 1
#define EICC_FEATURE_INNERCHN_SUPPORT 1
#define EICC_FEATURE_UNSECCHN_SUPPORT 1

#define EICC_BEFORE_RESET_CMD 0
#define EICC_AFTER_RESET_CMD 1

static inline void eicc_writel(u32 val, void *addr)
{
    writel(val, (unsigned long)((uintptr_t)addr));
}

static inline void eicc_writel_relaxed(u32 val, void *addr)
{
    writel(val, (unsigned long)((uintptr_t)addr));
}

static inline u32 eicc_readl(void *addr)
{
    return (u32)readl((unsigned long)((uintptr_t)addr));
}

#ifdef writel
#undef writel
#endif
#define writel eicc_writel

#ifdef writel_relaxed
#undef writel_relaxed
#endif
#define writel_relaxed eicc_writel_relaxed

#ifdef readl
#undef readl
#endif
#define readl eicc_readl

typedef s32 osl_spinlock_t;
/*lint -esym(528,osl_spin_lock_init) */
static inline int osl_spin_lock_init(osl_spinlock_t *lock)
{
    UNUSED(lock);
    return 0;
}
#define osl_spin_lock_irqsave(lock, __specific_flags)                                                                  \
    do {                                                                                                               \
        *lock = *lock;                                                                                                 \
        __specific_flags = __specific_flags;                                                                           \
        irq_lock();                                                                                                    \
    } while (0)
#define osl_spin_unlock_irqrestore(lock, __specific_flags)                                                             \
    do {                                                                                                               \
        *lock = *lock;                                                                                                 \
        __specific_flags = __specific_flags;                                                                           \
        irq_unlock();                                                                                                  \
    } while (0)

typedef u32 eiccsoc_ptr_t;

/*lint -esym(528,EICC_ADDR_LO) */
static inline u32 EICC_ADDR_LO(eiccsoc_ptr_t soc_addr)
{
    return (u32)soc_addr;
}
/*lint -esym(528,EICC_ADDR_HI) */
static inline u32 EICC_ADDR_HI(eiccsoc_ptr_t soc_addr)
{
    UNUSED(soc_addr);
    return (u32)0;
}
/*lint -esym(528,EICC_ADDR_MK) */
static inline eiccsoc_ptr_t EICC_ADDR_MK(u32 lo, u32 hi)
{
    UNUSED(hi);
    return (u32)lo;
}
/*lint -esym(528,eicc_get_slice_value) */
static inline u32 eicc_get_slice_value(void)
{
    return 0;
}
/*lint -esym(528,eicc_die) */
static inline void eicc_die(void *info, u32 info_len)
{
    UNUSED(info);
    UNUSED(info_len);
    return;
}

#define eicc_print_crit(fmt, ...) uart_printf_func("eicc: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define eicc_print_error(fmt, ...) uart_printf_func("eicc: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define eicc_print_warn(fmt, ...) uart_printf_func("eicc: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define eicc_print_notice(fmt, ...) uart_printf_func("eicc: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define eicc_print_info(fmt, ...) uart_printf_func("eicc: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define eicc_print_debug(fmt, ...) uart_printf_func("eicc: %s " fmt, __FUNCTION__, ##__VA_ARGS__)

#define eicc_print_always(fmt, ...) uart_printf_func("eicc: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define eicc_print_trace(fmt, ...)

#define eicc_roundup(x, n) (((x) + (n)-1) & (~((n)-1)))

int eicc_plat_init(void);

static inline void *eicc_malloc(u32 sz)
{
    return osl_malloc(sz);
}
static inline void eicc_free(void *ptr)
{
    osl_free(ptr);
}

void *eicc_pushmem_alloc(u32 size, eiccsoc_ptr_t *pa, u32 align);

static inline void *eicc_ioremap(u32 pa, u32 size)
{
    UNUSED(size);
    return (void *)(uintptr_t)pa;
}

static inline int eicc_request_irq(unsigned int irq, irq_handler_t handler, const char *name, void *arg)
{
    UNUSED(name);
    return SRE_HwiCreate((HWI_HANDLE_T)irq, 0xa0, INT_SECURE, (HWI_PROC_FUNC)handler, (HWI_ARG_T)arg);
}
static inline int eicc_enable_irq(unsigned int irq)
{
    SRE_HwiEnable(irq);
    return 0;
}
static inline int eicc_disable_irq(unsigned int irq)
{
    SRE_HwiDisable(irq);
    return 0;
}
int eicc_pmsr_init(void);
int eicc_rst_init(void);

#ifdef __cplusplus
}
#endif

#endif
