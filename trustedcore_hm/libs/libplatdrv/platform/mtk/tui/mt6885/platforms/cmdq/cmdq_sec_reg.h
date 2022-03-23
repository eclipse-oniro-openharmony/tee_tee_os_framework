/*
 * Copyright (C) 2015 MediaTek Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __CMDQ_SEC_REG_H__
#define __CMDQ_SEC_REG_H__

/*
 * secure dirver map region (via drApiMapPhys)
 * t-base200: 0x0004_0000 to 0x0007_FFFF
 * t-base300: 0x0008_0000 to 0x000D_FFFF = 384 K
 *
 *
 * 0x0008_0000 --- register mapping
 *       _B000   : GCE
 *       _C000   : (reserved)
 *       _D000   : CMDQ_SHARED_THR_COOKIE_REGION
 * 0x0009_0000 --- 0x0009_7EEE current config task
 * 0x0009_8000 --- 0x0009_EEEE previous task
 */

/* register mapping */
#define GCE_BASE_PA				(0x10228000)
#define CMD_BUFFER_BASE_PA			(0xA3D00000)
extern uint8_t *gCmdqRegBaseVA;
extern uint8_t *gCmdqSharedCookieVA;

#define CMDQ_ADDR_SHIFT(addr) (addr >> 3)
#define CMDQ_ADDR_REVERT(addr) (addr << 3)

#define REG_BASE_VA                   (0x00080000)
#define GCE_BASE_VA                   (gCmdqRegBaseVA)
#define CMDQ_SHARED_THR_COOKIE_REGION (gCmdqSharedCookieVA)

#define CMDQ_CURR_TASK_CMD_VA_BASE    (0x00090000)
#define CMDQ_PREV_TASK_CMD_VA_BASE    (0x00090000 + 0x00008000)

/* sectrace */
#define CMDQ_SECTRACE_VA	          (0x800000) /* D9 */

/* CMDQ THRx */
#define CMDQ_CORE_WARM_RESET         (GCE_BASE_VA + 0x000)
#define CMDQ_CURR_IRQ_STATUS         (GCE_BASE_VA + 0x010)
#define CMDQ_SECURE_IRQ_STATUS       (GCE_BASE_VA + 0x014)
#define CMDQ_CURR_LOADED_THR         (GCE_BASE_VA + 0x018)
#define CMDQ_THR_SLOT_CYCLES         (GCE_BASE_VA + 0x030)
#define CMDQ_THR_EXEC_CYCLES         (GCE_BASE_VA + 0x034)
#define CMDQ_THR_TIMEOUT_TIMER       (GCE_BASE_VA + 0x038)
#define CMDQ_BUS_CONTROL_TYPE        (GCE_BASE_VA + 0x040)
#define CMDQ_CURR_INST_ABORT         (GCE_BASE_VA + 0x020)
#define CMDQ_CURR_REG_ABORT          (GCE_BASE_VA + 0x050)

#define CMDQ_SECURITY_STA(id)        (GCE_BASE_VA + (0x030 * id) + 0x024)
#define CMDQ_SECURITY_SET(id)        (GCE_BASE_VA + (0x030 * id) + 0x028)
#define CMDQ_SECURITY_CLR(id)        (GCE_BASE_VA + (0x030 * id) + 0x02C)

#define CMDQ_SYNC_TOKEN_ID           (GCE_BASE_VA + 0x060)
#define CMDQ_SYNC_TOKEN_VAL          (GCE_BASE_VA + 0x064)
#define CMDQ_SYNC_TOKEN_UPD          (GCE_BASE_VA + 0x068)

#define CMDQ_GPR_R32(id)             (GCE_BASE_VA + (0x004 * id) + 0x80)
#define CMDQ_GPR_R32_PA(id)          (GCE_BASE_PA + (0x004 * id) + 0x80)

#define CMDQ_THR_WARM_RESET(id)      (GCE_BASE_VA + (0x080 * id) + 0x100)
#define CMDQ_THR_ENABLE_TASK(id)     (GCE_BASE_VA + (0x080 * id) + 0x104)
#define CMDQ_THR_SUSPEND_TASK(id)    (GCE_BASE_VA + (0x080 * id) + 0x108)
#define CMDQ_THR_CURR_STATUS(id)     (GCE_BASE_VA + (0x080 * id) + 0x10C)
#define CMDQ_THR_IRQ_STATUS(id)      (GCE_BASE_VA + (0x080 * id) + 0x110)
#define CMDQ_THR_IRQ_ENABLE(id)      (GCE_BASE_VA + (0x080 * id) + 0x114)
#define CMDQ_THR_SECURITY(id)        (GCE_BASE_VA + (0x080 * id) + 0x118)
#define CMDQ_THR_CURR_ADDR(id)       (GCE_BASE_VA + (0x080 * id) + 0x120)
#define CMDQ_THR_END_ADDR(id)        (GCE_BASE_VA + (0x080 * id) + 0x124)
#define CMDQ_THR_EXEC_CNT(id)        (GCE_BASE_VA + (0x080 * id) + 0x128)
#define CMDQ_THR_WAIT_TOKEN(id)      (GCE_BASE_VA + (0x080 * id) + 0x130)
#define CMDQ_THR_CFG(id)             (GCE_BASE_VA + (0x080 * id) + 0x140)
#define CMDQ_THR_INST_CYCLES(id)     (GCE_BASE_VA + (0x080 * id) + 0x150)
#define CMDQ_THR_INST_THRESX(id)     (GCE_BASE_VA + (0x080 * id) + 0x154)


#define CMDQ_REG_GET32(addr)        (*(volatile unsigned int*)(addr))
#define CMDQ_REG_GET16(addr)        ((*(volatile unsigned int*)(addr)) & 0x0000FFFF)
#define CMDQ_REG_SET32(addr, val)   (*(volatile unsigned int*)(addr) = val)

/* IRQ: CMDQ_SECURE_IRQ_ID should be same as number in device tree*/
/* The real IRQ number is the number in device tree plus 32 */
#define GIC_PRIVATE_SIGNALS	(32)
#define CMDQ_SECURE_IRQ_ID	(GIC_PRIVATE_SIGNALS + 155)

/* shared THR cnt */
#define CMDQ_SHARED_IRQ_RAISED_FLAG  (CMDQ_SHARED_THR_COOKIE_REGION + CMDQ_SEC_SHARED_IRQ_RAISED_OFFSET)
#define CMDQ_THR_SHARED_EXEC_CNT(id) (CMDQ_SHARED_THR_COOKIE_REGION + CMDQ_SEC_SHARED_THR_CNT_OFFSET + (0x004 * id))

#endif				/* __CMDQ_SEC_REG_H__ */
