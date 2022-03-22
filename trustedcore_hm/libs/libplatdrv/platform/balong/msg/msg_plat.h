/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */

#ifndef _MSG_PLAT_H
#define _MSG_PLAT_H
#include <drv_module.h>
#include <sre_hwi.h>

#include <osl_balong.h>
#include <osl_list.h>
#include <securec.h>
#include "bsp_shared_ddr.h"

#include "bsp_msg.h"
#include "msg_sha_def.h"
// platform definition
#define MSG_CURRENT_CORE_ID MSG_CID_TEE
#define MSG_CURRENT_CORE_MID DRV_MID_MSG

#define msg_crit(fmt, ...) uart_printf_func("msg: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define msg_err(fmt, ...) uart_printf_func("msg: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define msg_warn(fmt, ...) uart_printf_func("msg: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define msg_print(fmt, ...) uart_printf_func("msg: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define msg_always(fmt, ...) uart_printf_func("msg: %s " fmt, __FUNCTION__, ##__VA_ARGS__)
#define msg_trace(fmt, ...)

#define local_irq_save(__specific_flags) \
    do {                                 \
        (void)__specific_flags;          \
        irq_lock();                      \
    } while (0)
#define local_irq_restore(__specific_flags) \
    do {                                    \
        (void)__specific_flags;             \
        irq_unlock();                       \
    } while (0)

#define msg_roundup(x, n) (((x) + (n)-1) & (~((n)-1)))

int msg_plat_init(void);
void *msg_dma_alloc(u32 size, unsigned long *pa, u32 align);

#endif
