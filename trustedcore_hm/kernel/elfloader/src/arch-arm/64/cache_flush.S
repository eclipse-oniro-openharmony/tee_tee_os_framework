/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader flush function
 * Create: 2020-12
 */
#include <machine/assembler.h>

/*
 * +------------------------------------+
 * |      way    way    way    way      |
 * |     +---+  +---+  +---+  +---+     |
 * |     |   |  |   |  |   |  |   |     |
 * |     |   |  |   |  |   |  |   |     |
 * | set +---+  +---+  +---+  +---+     |
 * |     |   |  |   |  |   |  |   |     |
 * |     |   |  |   |  |   |  |   |     |
 * |     +---+  +---+  +---+  +---+     |
 * |                                    |
 * +------------------------------------+
 *              cache level
 *
 * This algorithm is get from ARM's <Programmer’s Guide for ARMv8-A>
 */
clean_dcache_to_pou:
	mrs x0, clidr_el1		// get nr_cache_level from clidr_el1[26:24]
	and x3, x0, #0x07000000
	lsr x3, x3, #23
	cbz x3, finished		// if nr_cache_level == 0, no need to clean
	mov x10, #0			// for (x10 = 0; x10 < nr_cache_level; x10++)
	mov x8, #1
loop1:
	add x2, x10, x10, lsr #1
	lsr x1, x0, x2			// get cache type bits from clidr_el1 (x0)
	and x1, x1, #0x7		// 000 No cache, 001 icache only, 010 dcache only, 011 i+d cache, 100 unified cache
	cmp x1, #2			// no cache or icache don't need to clean
	b.lt skip
	msr csselr_el1, x10		// select current cache level in csselr_el1
	isb
	mrs x1, ccsidr_el1		// ccsidr_el1: [27-13]nr_sets, [12:3]assoc, [2:0]line_size
	and x2, x1, #7			// x2 = log2(line_size)-4, i.e.: cache line size=64B, x2=6-4=2
	and x2, x2, #4
	ubfx x4, x1, #3, #10		// x4 = x1[12:3] = assoc - 1
	clz x5, x4
	lsl x9, x4, x5			// x9 = assoc - 1
	lsl x16, x8, x5
loop2:
	ubfx x7, x1, #13, #15		// x7 = x1[27:13] = set - 1
	lsl x7, x7, x2
	lsl x17, x8, x2
loop3:
	orr x11, x10, x9
	orr x11, x11, x7
	dc cisw, x11
	subs x7, x7, x17
	b.ge loop3
	subs x9, x9, x16
	b.ge loop2
skip:
	add x10, x10, #2
	cmp x3, x10
	dsb ish
	b.gt loop1
finished:
	ret

BEGIN_FUNC(flush_cache_all)
	mov x12, x30		// save lr to x12
	dsb sy
	bl clean_dcache_to_pou	// clean dcache to pou
	dsb sy
	ic ialluis		// clean icache to pou
	dsb sy
	isb
	ret x12
END_FUNC(flush_cache_all)
