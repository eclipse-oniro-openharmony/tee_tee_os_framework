/*
 * npu_irq_common.h
 *
 * Copyright (c) 2012-2020 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef __NPU_IRQ_COMMON_H
#define __NPU_IRQ_COMMON_H

#include <string.h>
#include <list.h>
#include <sre_hwi.h>
#include <sre_typedef.h>
#include <secure_gic_common.h>
#include <tee_defines.h>
#include "npu_log.h"

#define IRQF_TRIGGER_NONE	0x00000000
#define IRQF_TRIGGER_RISING	0x00000001
#define IRQF_TRIGGER_FALLING	0x00000002
#define IRQF_TRIGGER_HIGH	0x00000004
#define IRQF_TRIGGER_LOW	0x00000008
#define IRQF_TRIGGER_MASK	(IRQF_TRIGGER_HIGH | IRQF_TRIGGER_LOW | \
				IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING)
#define IRQF_TRIGGER_PROBE	0x00000010

typedef enum {
	IRQ_NONE,
	IRQ_HANDLED
} irqreturn_t;
typedef irqreturn_t (*irq_handler_t)(void *);

static inline int request_irq(unsigned int irq, irq_handler_t handler,
	unsigned long flags, const char *name, void *arg)
{
	UNUSED(flags);
	UNUSED(name);

	UINT32 ret = SRE_HwiCreate((HWI_HANDLE_T)(irq), 0xa0, INT_SECURE, (HWI_PROC_FUNC)handler, (HWI_ARG_T)arg);
	if (ret != SRE_OK) {
		NPU_DRV_ERR("SRE_HwiCreate irq %d errorNO 0x%x\n", irq, ret);
		return ret;
	}

	ret = SRE_HwiEnable(irq);
	if (ret != SRE_OK) {
		NPU_DRV_ERR("SRE_HwiEnable irq %d errorNO 0x%x\n", irq, ret);
		return ret;
	}

	NPU_DRV_INFO("request_irq  irq = %d  ret = %d success", irq, ret);
	return ret;
}

static inline void free_irq(unsigned int irq, void *arg)
{
	UNUSED(arg);
	UINTPTR ret;

	ret = SRE_HwiDisable(irq);
	if (ret != SRE_OK) {
		NPU_DRV_ERR("SRE_HwiDisable irq %d errorNO 0x%x\n", irq, ret);
		return;
	}

	ret = SRE_HwiDelete((HWI_HANDLE_T)irq);
	if (ret != SRE_OK) {
		NPU_DRV_ERR("SRE_HwiDelete irq %d errorNO 0x%x\n", irq, ret);
		return;
	}
}

#endif /* __NPU_IRQ_COMMON_H */
