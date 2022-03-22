/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_barrier.h"

/* taken from arch/arm/include/asm/barrier.h */

#if defined(__arm64__)
/* This is memmory barrier for ARM64 */

#define dsb(opt) asm volatile("dsb " #opt : : : "memory")

#elif defined(__arm__)
/* This is memmory barrier for ARM */

#define dsb() __asm__ __volatile__("dsb" : : : "memory")

#else
#error This is a place holder for platform specific memory barrier implementation
#define dsb()
#endif
/* This is a plac holder for L2 cache sync function */
#define SASI_PAL_L2_CACHE_SYNC() \
    do {                         \
    } while (0)

#if defined(__arm64__)
#define mb()  dsb(sy)
#define rmb() dsb(ld)
#define wmb() dsb(st)
#else
#define mb()                      \
    do {                          \
        dsb();                    \
        SASI_PAL_L2_CACHE_SYNC(); \
    } while (0)
#define rmb() dsb()
#define wmb() mb()
#endif

void SaSi_PalWmb(void)
{
    wmb();
}

void SaSi_PalRmb(void)
{
    rmb();
}
