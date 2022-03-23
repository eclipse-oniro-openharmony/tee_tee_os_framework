/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Bit map
 * Author: Linux SDK team
 * Create: 2019-08-12
 */

#ifndef __KLAD_BITMAPS_H__
#define __KLAD_BITMAPS_H__

#include "securec.h"
#include "hi_type_dev.h"

#define BITS_PER_BYTE       8
#undef BITS_PER_LONG
#define BITS_PER_LONG       (BITS_PER_BYTE * sizeof(unsigned long))
#define bit_mask(nr)        (1UL << ((nr) % BITS_PER_LONG))
#define bit_word(nr)        ((nr) / BITS_PER_LONG)
#define div_round_up(n, d)   (((n) + (d) - 1) / (d))
#undef bits_to_longs
#define bits_to_longs(nr)   div_round_up(nr, BITS_PER_LONG)
#define declare_bitmap(name,bits) \
                        unsigned long name[bits_to_longs(bits)]

/*
 * bitmap function.
 */
static inline void bitmap_zero(unsigned long *dst, int nbits)
{
    const int len = bits_to_longs(nbits) * sizeof(unsigned long);
    if (memset_s(dst, len, 0, bits_to_longs(nbits) * sizeof(unsigned long)) != EOK) {
        return;
    }
}

static inline void bitmap_setbit(unsigned int nr, volatile unsigned long *addr)
{
    const unsigned long mask = bit_mask(nr);
    unsigned long *p = ((unsigned long *)addr) + bit_word(nr);

    *p  |= mask;
}

static inline void bitmap_clrbit(unsigned int nr, volatile unsigned long *addr)
{
    const unsigned long mask = bit_mask(nr);
    unsigned long *p = ((unsigned long *)addr) + bit_word(nr);

    *p &= ~mask;
}

unsigned long _find_first_zero_bit(const unsigned long *addr, unsigned long size);
unsigned long _find_first_bit(const unsigned long *addr, unsigned long size);
unsigned long _find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset);
unsigned long _find_next_zero_bit(const unsigned long *addr, unsigned long size, unsigned long offset);

#define for_each_set_bit(bit, addr, size) \
    for ((bit) = find_first_bit((addr), (size));        \
         (bit) < (size);                    \
         (bit) = find_next_bit((addr), (size), (bit) + 1))

#define for_each_zero_bit(bit, addr, size) \
    for ((bit) = find_first_zero_bit((addr), (size));        \
         (bit) < (size);                    \
         (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

#define clear_bit(nr, addr) bitmap_clrbit(nr, addr)
#define set_bit(nr, addr) bitmap_setbit(nr, addr)
#define find_first_zero_bit(addr, size) _find_first_zero_bit(addr, size)
#define find_first_bit(addr, size) _find_first_bit(addr, size)
#define find_next_bit(addr, size, offset) _find_next_bit(addr, size, offset)
#define find_next_zero_bit(addr, size, offset) _find_next_zero_bit(addr, size, offset)

#endif      /* __DEMUX_BITMAPS_H__ */
