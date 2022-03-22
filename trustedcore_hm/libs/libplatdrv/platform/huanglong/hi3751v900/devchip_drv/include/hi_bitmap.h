/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: bit map impl
 */

#ifndef __HI_BITMAP_H__
#define __HI_BITMAP_H__

#include "hi_type_dev.h"

#define BITS_PER_BYTE       8
#define BITS_PER_LONG       (BITS_PER_BYTE * sizeof(unsigned long))
#define BIT_MASK(nr)        (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)        ((nr) / BITS_PER_LONG)
#define DIV_ROUND_UP(n,d)   (((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr)   DIV_ROUND_UP(nr, BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) unsigned long name[BITS_TO_LONGS(bits)]

/*
 * bitmap function.
 */
static inline void bitmap_zero(unsigned long *dst, int nbits)
{
    int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
    memset_s(dst, len, 0, len);
}

static inline void bitmap_setbit(unsigned int nr, volatile unsigned long *addr)
{
    const unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

    *p  |= mask;
}

static inline void bitmap_clrbit(unsigned int nr, volatile unsigned long *addr)
{
    const unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

    *p &= ~mask;
}

unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size);
unsigned long find_first_bit(const unsigned long *addr, unsigned long size);
unsigned long find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset);
unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size, unsigned long offset);

#define for_each_set_bit(bit, addr, size) \
    for ((bit) = find_first_bit((addr), (size));        \
         (bit) < (size);                    \
         (bit) = find_next_bit((addr), (size), (bit) + 1))

#define for_each_zero_bit(bit, addr, size) \
    for ((bit) = find_first_zero_bit((addr), (size));        \
         (bit) < (size);                    \
         (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

#endif /* __HI_BITMAP_H__ */
