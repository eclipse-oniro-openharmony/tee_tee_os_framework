/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: interrupt interface
 *              irq_num is defined in pal_interrupt_plat.h
 *              interface is implemented in pal_interrupt_plat.h
 * Author     : l00370476, liuchong13@huawei.com
 * Create     : 2018/08/13
 */
#ifndef __PAL_INTERRUPT_H__
#define __PAL_INTERRUPT_H__
#include "pal_types.h"
#include "pal_interrupt_plat.h"

typedef void (*pal_irq_handle)(u32 irq_num);

/**
 * @brief      : registe interrupt
 * @param[in]  : irq_num interrupt number
 * @return     : ::err_bsp_t
 */
err_bsp_t pal_irq_register(u32 irq_num, pal_irq_handle handler);

/**
 * @brief      : enable interrupt
 * @param[in]  : irq_num interrupt number
 */
err_bsp_t pal_irq_enable(u32 irq_num);

/**
 * @brief      : disable interrupt
 * @param[in]  : irq_num interrupt number
 */
err_bsp_t pal_irq_disable(u32 irq_num);

/**
 * @brief      : clear pending interrupt
 * @param[in]  : irq_num interrupt number
 */
err_bsp_t pal_irq_clear(u32 irq_num);

#endif /* __PAL_INTERRUPT_H__ */

