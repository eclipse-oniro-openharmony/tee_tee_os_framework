/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee npu register.
 * Author: SDK
 * Create: 2020-02-21
 */

#ifndef __TEE_DRV_NPU_REG_H__
#define __TEE_DRV_NPU_REG_H__

/* add include here */
#ifdef __cplusplus
extern "C"
{
#endif

/* NPU config regs */
#define NPU_REG_BASE  0x4000000

#define BIT(x) (1<<(x))

#ifndef readl
#define readl(addr)             (*(volatile u32 *)(addr))
#endif

#ifndef writel
#define writel(val, addr)       (*(volatile u32 *)(addr) = (val))
#endif

#define NPU_REG_READ(base, offset)  readl((void *)(uintptr_t)((base) + (offset)))
#define NPU_REG_WRITE(base, offset, value)   writel((value), (void *)(uintptr_t)((base) + (offset)))
#define NPU_SUB_REG_READ(base, subbase, offset)  readl((void *)(uintptr_t)((base) + (subbase) + (offset)))
#define NPU_SUB_REG_WRITE(base, subbase, offset, value)   writel(value, (void*)(uintptr_t)((base) + (subbase) + (offset)))

#define read64(addr)             (*(volatile u64 *)(addr))
#define write64(val, addr)       (*(volatile u64 *)(addr) = (val))

#define NPU_REG64_READ(base, offset)  read64((void *)(uintptr_t)((base) + (offset)))
#define NPU_REG64_WRITE(base, offset, value)   write64((value), (void *)(uintptr_t)((base) + (offset)))
#define NPU_SUB_REG64_READ(base, subbase, offset)  read64((void *)(uintptr_t)((base) + (subbase) + (offset)))
#define NPU_SUB_REG64_WRITE(base, subbase, offset, value)   write64(value, (void*)(uintptr_t)((base) + (subbase) + (offset)))

#ifdef __cplusplus
}
#endif
#endif /* end #ifndef __TEE_DRV_NPU_REG_H__ */

