/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: irq engine control
 * Author     : l00414685
 * Create     : 2020/03/30
 */
#ifndef __SECENG_IRQCTRL_H__
#define __SECENG_IRQCTRL_H__
#include "pal_interrupt.h"

#ifdef FEATURE_ALARM_REGISTER_ENABLE
static inline err_bsp_t seceng_irq_init(u32 irq_num, pal_irq_handle handler)
{
	err_bsp_t ret;

	/* clear pending interrupt */
	ret = pal_irq_clear(irq_num);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = pal_irq_register(irq_num, handler);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = pal_irq_enable(irq_num);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	return ret;
}
#else
static inline err_bsp_t seceng_irq_init(u32 irq_num, pal_irq_handle handler)
{
	err_bsp_t ret;

	UNUSED(handler);
	ret = pal_irq_disable(irq_num);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	return ret;
}
#endif

#endif
