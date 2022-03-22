/*
 * npu_base_define.h
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

#ifndef __NPU_BASE_DEFINE_H__
#define __NPU_BASE_DEFINE_H__
#include <stdlib.h>
#include <stdint.h>
#include <sre_typedef.h>

#define u64 uint64_t
#define u32 uint32_t
#define u16 uint16_t
#define u8  uint8_t
#define s32 int32_t

#define NPU_DEV_NUM 			1

#define NPU_MODEL_STREAM_NUM	2

#define NPU_RT_TASK_SIZE		64

#define NPU_HWTS_SQ_SLOT_SIZE	128
#define NPU_HWTS_CQ_SLOT_SIZE	16
#define NPU_MAX_HWTS_SQ_DEPTH	1024
#define NPU_MAX_HWTS_CQ_DEPTH	1024

#define UNUSED(expr) \
	do { \
		(void)(expr); \
	} while (0)

typedef enum secure_state {
	NPU_NONSEC = 0,
	NPU_SEC = 1,
	NPU_ISPNN = 2,
	NPU_INIT = 3,
	NPU_SEC_END
} secure_state_t;

typedef enum npu_power_stage {
	DEVDRV_PM_DOWN,
	DEVDRV_PM_UP
} npu_power_stage_t;

#define isb() __asm__ __volatile__ ("isb" : : : "memory")
#define dsb() __asm__ __volatile__ ("dsb" : : : "memory")
#define dmb() __asm__ __volatile__ ("dmb" : : : "memory")
static inline void mb()
{
	asm volatile("dsb sy"
	             :
	             :
	             : "memory");
}


#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

static inline void NPU_DWB(void) /* drain write buffer */
{
	asm volatile("dsb");
}


static inline void npu_writel(unsigned val, unsigned addr)
{
	NPU_DWB();
	(*(volatile unsigned *)(addr)) = (val);
	NPU_DWB();
}

static inline unsigned npu_readl(unsigned addr)
{
	return (*(volatile unsigned *)(addr));
}

static inline void npu_write64(uint64_t val, uint64_t addr)
{
    NPU_DWB();
    asm volatile("strd %0, [%1]" : : "r" (val), "r" (addr));
    NPU_DWB();
}

static inline uint64_t npu_read64(uint64_t addr)
{
    uint64_t val;
    asm volatile("ldrd %0, [%1]" : "=r" (val) : "r" (addr));
    return val;
}

#define REG_MASK(len, offset)                                   \
    (((len) == 64) ? 0xFFFFFFFFFFFFFFFF : (((1ULL << (len)) - 1) << (offset)))

#define REG_FIELD_MAKE(val, len, offset)                        \
    ((((uint64_t)val) << (offset)) & REG_MASK((len), (offset)))

#define REG_FIELD_EXTRACT(reg, len, offset)                      \
    (((reg) & REG_MASK((len), (offset))) >> (offset))

#define REG_FIELD_INSERT(reg, len, offset, val)                 \
    ((reg) = ((reg) & (~ REG_MASK((len), (offset))))            \
            | REG_FIELD_MAKE((val), (len), (offset)))

#define TS_BITMAP_CLR(val, pos)         ((val) &= (~(1ULL << (pos))))

#endif /* __NPU_BASE_DEFINE_H__ */
