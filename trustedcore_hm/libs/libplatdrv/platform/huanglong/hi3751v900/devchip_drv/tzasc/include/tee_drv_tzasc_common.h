/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: common define and func for tzasc
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#ifndef _TEE_DRV_TZASC_COMMON_H_
#define _TEE_DRV_TZASC_COMMON_H_

#include "hi_tee_drv_os_hal.h"

/*
 * Suppress GCC warning on expansion of the macro with no argument:
 * 'ISO C99 requires at least one argument for the "..." in a variadic macro'
 * Occurs when '-pedantic' is combined with '-std=gnu99'.
 * Suppression applies only to this file and the expansion of macros defined in
 * this file.
 */
#pragma GCC system_header

#undef TEE_DRV_TZASC_DEBUG
#undef TZASC_REG_TRACE

#ifdef CFG_HI_TEE_FPGA_SUPPORT
#define TEE_DRV_TZASC_DEBUG
#endif

#define tzasc_printf(format, args...)   hi_tee_drv_hal_printf(format, ##args)
#define tzasc_error(format, args...)    hi_tee_drv_hal_printf("[%s][%d][ERROR] "format, __func__, __LINE__, ##args)
#ifdef TEE_DRV_TZASC_DEBUG
#define tzasc_debug(format, args...)    hi_tee_drv_hal_printf("[%s][%d][DEBUG] "format, __func__, __LINE__, ##args)
#else
#define tzasc_debug(fmt...)
#endif

#define tzasc_assert(expr) \
    do { \
        if (!(expr)) { \
            tzasc_printf("TZASC ASSERT: Assertion [%s] failed. File[%s] Func[%s] Line[%d]\n", \
                         #expr, __FILE__, __func__, __LINE__); \
            tzasc_sys_reset(); \
        } \
    } while (0)

#define tzasc_dsb()     asm volatile ("dsb")

#ifdef TZASC_REG_TRACE
#define tzasc_read(addr) \
    ({ \
        unsigned int __v = *(volatile unsigned int *)(hi_tee_drv_hal_phys_to_virt(addr)); \
        tzasc_dsb(); \
        hi_tee_drv_hal_printf("read %p = 0x%X\n", (unsigned int *)(hi_tee_drv_hal_phys_to_virt(addr)), __v); \
        __v; \
    })

#define tzasc_write(val, addr)  \
    do { \
        tzasc_dsb(); \
        hi_tee_drv_hal_printf("write %p = 0x%X\n", (unsigned int *)(hi_tee_drv_hal_phys_to_virt(addr)), val); \
        *(volatile unsigned int *)(hi_tee_drv_hal_phys_to_virt(addr)) = (val); \
        tzasc_dsb(); \
    } while (0)

#else
#define tzasc_read(addr) \
    ({ \
        unsigned int __v = *(volatile unsigned int *)(hi_tee_drv_hal_phys_to_virt(addr)); \
        tzasc_dsb(); \
        __v; \
    })

#define tzasc_write(val, addr) \
    do { \
        tzasc_dsb(); \
        *(volatile unsigned int *)(hi_tee_drv_hal_phys_to_virt(addr)) = (val); \
        tzasc_dsb(); \
    } while (0)
#endif

#define bits_mask(nbits)                    ((1u << (nbits)) - 1u)
#define get_bits_shift(x, nbits, nshift)    (((x) >> (nshift)) & bits_mask(nbits))
#define bits_shift_mask(nbits, nshift)      (bits_mask(nbits) << (nshift))
#define bits_shift_val(x, nbits, nshift)    (((x) & bits_mask(nbits)) << (nshift))

unsigned int tzasc_get_bit(unsigned long long addr, unsigned int shift);
void tzasc_set_bit(unsigned long long addr, unsigned int shift);
void tzasc_clear_bit(unsigned long long addr, unsigned int shift);

void tzasc_dump_addr(const char *name, char *addr, unsigned int size);
void tzasc_sys_reset(void);
void tzasc_random_delay(void);
int tzasc_request_irq(unsigned int irq, void *handler, const void *arg);
void tzasc_unregister_irq(unsigned int irq);
void tzasc_sec_write(unsigned int value, unsigned int addr);

static inline unsigned int tzasc_read_bits(unsigned long long addr, unsigned int shift, unsigned int bits)
{
    unsigned int reg_val = tzasc_read((unsigned int)addr);
    return get_bits_shift(reg_val, bits, shift);
}

static inline void tzasc_write_bits(unsigned long long addr, unsigned int value, unsigned int shift, unsigned int bits)
{
    unsigned int reg_val = tzasc_read((unsigned int)addr);
    reg_val &= ~(bits_shift_mask(bits, shift));
    reg_val |= bits_shift_val(value, bits, shift);
    tzasc_sec_write(reg_val, (unsigned int)addr);
}

#endif /* _TEE_DRV_TZASC_COMMON_H_ */
