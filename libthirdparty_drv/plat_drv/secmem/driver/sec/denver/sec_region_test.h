/*
 * Copyright @ Huawei Technologies Co., Ltd. 2019-2028. All rights reserved.
 * Description: secure ddr memory's secure test cases
 * Author: x00431728
 * Create: 2019-03-29
 */
#ifndef __SEC_REGION_TEST_H__
#define __SEC_REGION_TEST_H__

#include <global_ddr_map.h>

#define readl(addr) (*(volatile u32 *)addr)

#define SUB_RGN_INIT_VALUE  0xffffffff
#define SEGMENT_NUM_1 0x1
#define SEGMENT_NUM_1_RGN_3 0xfffffffe
#define SEGMENT_NUM_1_RGN_2 0xffffffff

#define SEGMENT_NUM_16 0x10
#define SEGMENT_NUM_16_RGN_3 0xffff0000
#define SEGMENT_NUM_16_RGN_2 0xffffffff

#define SEGMENT_NUM_32 0x20
#define SEGMENT_NUM_32_RGN_3 0x0
#define SEGMENT_NUM_32_RGN_2 0xffffffff

#define SEGMENT_NUM_48 0x30
#define SEGMENT_NUM_48_RGN_3 0x0
#define SEGMENT_NUM_48_RGN_2 0xffff0000

#define PAGES_8K  2
#define PAGES_64K 16
#define PAGES_512K 128 /* 128 * 4KB = 512KB */
#define PAGES_1M 256 /* 256 * 4KB = 1024KB(1MB) */
#define PAGES_2M (256 * 2)
#define NORMAL_REGION_START_ADDR 0xd0000000U /* reserved zone */
#define NORMAL_REGION_MAP0_VALUE 0x8000d000
#define NORMAL_REGION_MAP1_VALUE 0xc000d000
#define NORMAL_REGION_INIT_VALUE 0x0

#define LPMCU_START_ADDR HISI_RESERVED_LPMCU_PHYMEM_BASE
struct test {
	char *name;
	int (*func)();
};

int sec_region_test(void);

#endif
