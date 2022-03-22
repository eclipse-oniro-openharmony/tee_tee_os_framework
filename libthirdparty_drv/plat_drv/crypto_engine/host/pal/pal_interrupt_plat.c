/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: interrupt adapter
 * Author     : m00475438
 * Create     : 2018/09/03
 */
#include <pal_log.h>
#include <pal_interrupt.h>
#include <common_utils.h>
#include <pal_libc.h>

/* set the module to which the file belongs
 * each .C file needs to be configured
 */
#define BSP_THIS_MODULE               BSP_MODULE_SYS

/**
 * @brief      : register interrupt handler
 * @param[in]  : irq_num interrupt number
 * @param[in]  : handler interrupt callback handler
 */
err_bsp_t pal_irq_register(u32 irq_num, pal_irq_handle handler)
{
	UNUSED(irq_num);
	UNUSED(handler);
	return ERR_DRV(ERRCODE_UNSUPPORT);
}

/**
 * @brief      : enable interrupt
 * @param[in]  : irq_num interrupt number
 */
err_bsp_t pal_irq_enable(u32 irq_num)
{
	UNUSED(irq_num);
	return ERR_DRV(ERRCODE_UNSUPPORT);
}

/**
 * @brief      : disable interrupt
 * @param[in]  : irq_num interrupt number
 */
err_bsp_t pal_irq_disable(u32 irq_num)
{
	UNUSED(irq_num);
	return BSP_RET_OK;
}

/**
 * @brief      : clear pending interrupt
 * @param[in]  : irq_num interrupt number
 */
err_bsp_t pal_irq_clear(u32 irq_num)
{
	/* nothing to do */
	UNUSED(irq_num);
	return ERR_DRV(ERRCODE_UNSUPPORT);
}

