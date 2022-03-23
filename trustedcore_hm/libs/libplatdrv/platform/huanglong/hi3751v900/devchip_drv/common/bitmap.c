/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: bit map impl
 */

#include "string.h"
#include "hi_bitmap.h"

static unsigned long find_first_bit_in_word(unsigned long word)
{
    unsigned long result = 0UL;
    unsigned long bit_cnt = BITS_PER_LONG;
    unsigned long mask = 0UL;

    do {
        bit_cnt /= 2;
        mask = (1UL << bit_cnt) - 1;
        if ((word & mask) == 0UL) {
            result += bit_cnt;
            word >>= bit_cnt;
        }
    } while (bit_cnt > 0UL);

    return result;
}

unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
    const unsigned long *cur = addr;
    unsigned long cur_result = 0UL;
    unsigned long temp;

    while (size >= BITS_PER_LONG) {
        temp = *cur;
        cur++;
        if ((~temp) != 0UL) {
            goto found;
        }
        cur_result += BITS_PER_LONG;
        size -= BITS_PER_LONG;
    }

    if (size == 0UL) {
        return cur_result;
    }

    temp = (*cur) | ((~0UL) << size);

    /* there is no bits zero */
    if (temp == (~0UL)) {
        return cur_result + size;
    }
found:
    return cur_result + find_first_bit_in_word(~temp);
}

unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
    const unsigned long *cur = addr;
    unsigned long cur_result = 0UL;
    unsigned long temp;

    while (size >= BITS_PER_LONG) {
        temp = *cur;
        cur++;
        if (temp != 0UL) {
            goto found;
        }
        cur_result += BITS_PER_LONG;
        size -= BITS_PER_LONG;
    }

    if (size == 0UL) {
        return cur_result;
    }

    temp = (*cur) & ((~0UL) >> (BITS_PER_LONG - size));

    /* there is no bit set */
    if (temp == 0UL) {
        return cur_result + size;
    }
found:
    return cur_result + find_first_bit_in_word(temp);
}

unsigned long find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset)
{
    const unsigned long *cur = addr + (offset / BITS_PER_LONG);
    unsigned long cur_result = (offset / BITS_PER_LONG) * BITS_PER_LONG;
    unsigned long temp;

    if (offset >= size) {
        return size;
    }

    size -= cur_result;
    offset %= BITS_PER_LONG;

    if (offset != 0UL) {
        temp = *(cur++);
        temp &= ((~0UL) << offset);
        if (size < BITS_PER_LONG) {
            goto find_first;
        }
        if (temp != 0UL) {
            goto find_middle;
        }
        size -= BITS_PER_LONG;
        cur_result += BITS_PER_LONG;
    }

    while (size >= BITS_PER_LONG) {
        temp = *cur;
        cur++;
        if (temp != 0) {
            goto find_middle;
        }
        cur_result += BITS_PER_LONG;
        size -= BITS_PER_LONG;
    }

    if (size == 0) {
        return cur_result;
    }

    temp = *cur;

find_first:
    temp &= ((~0UL) >> (BITS_PER_LONG - size));
    /* there is no bit set */
    if (temp == 0UL) {
        return cur_result + size;
    }
find_middle:
    return cur_result + find_first_bit_in_word(temp);
}

unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size, unsigned long offset)
{
    const unsigned long *cur = addr + (offset / BITS_PER_LONG);
    unsigned long cur_result = (offset / BITS_PER_LONG) * BITS_PER_LONG;
    unsigned long temp;

    if (offset >= size) {
        return size;
    }

    size -= cur_result;
    offset %= BITS_PER_LONG;
    if (offset != 0UL) {
        temp = *(cur++);
        temp &= ((~0UL) << offset);
        if (size < BITS_PER_LONG) {
            temp |= ((1UL << offset) - 1UL);
            goto find_first;
        }
        if (temp != ((~0UL) << offset)) {
            temp |= ((1UL << offset) - 1UL);
            goto find_middle;
        }
        size -= BITS_PER_LONG;
        cur_result += BITS_PER_LONG;
    }

    while (size >= BITS_PER_LONG) {
        temp = *cur;
        cur++;
        if (temp != (~0UL)) {
            goto find_middle;
        }
        cur_result += BITS_PER_LONG;
        size -= BITS_PER_LONG;
    }
    if (size == 0) {
        return cur_result;
    }

    temp = *cur;

find_first:
    temp &= ((~0UL) >> (BITS_PER_LONG - size));
    /* there is no bit zero */
    if (temp == ((~0UL) >> (BITS_PER_LONG - size))) {
        return cur_result + size;
    }
find_middle:
    return cur_result + find_first_bit_in_word(~temp);
}

