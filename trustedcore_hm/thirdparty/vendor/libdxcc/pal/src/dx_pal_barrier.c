/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#include "dx_pal_barrier.h"

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
#define DX_PAL_L2_CACHE_SYNC() \
    do {                       \
    } while (0)

#if defined(__arm64__)
#define mb()  dsb(sy)
#define rmb() dsb(ld)
#define wmb() dsb(st)
#else
#define mb()                    \
    do {                        \
        dsb();                  \
        DX_PAL_L2_CACHE_SYNC(); \
    } while (0)
#define rmb() dsb()
#define wmb() mb()
#endif

void DX_PAL_Wmb()
{
    // wmb();
}

void DX_PAL_Rmb()
{
    // rmb();
}
