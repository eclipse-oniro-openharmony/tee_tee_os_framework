/*
 * Copyright @ Huawei Technologies Co., Ltd. 2019-2028. All rights reserved.
 * Description: ddr interface test
 * Author: x00431728
 * Create: 2019-03-29
 */
#include <mem_page_ops.h>
#include <tee_log.h>
#include <sec_region_ops.h>
#include <ddr_sec_feature.h>
#include "sec_region.h"
#include "sec_region_test.h"
#include <stdlib.h>
#include <soc_acpu_baseaddr_interface.h>
#include <soc_dmss_interface.h>

u32 g_feature_npages[SUB_RGN_FEATURE_MAX] = {0};
struct sglist *g_sglist = NULL;

extern SUB_RGN_CFG g_sub_rgn_cfg_table[SUB_RGN_FEATURE_MAX];
extern NORMAL_RGN_CFG g_normal_rgn_cfg_table[NORMAL_RGN_MAX_NUM];

static void sglist_init(u32 feature_num, u32 sgment_num)
{
	u32 i;
	g_sglist->infoLength = sgment_num;

	for (i = 0; i < sgment_num; i++) {
		(g_sglist->info[i]).phys_addr = g_sub_rgn_cfg_table[feature_num].start_addr + g_feature_npages[feature_num] * PAGE_SIZE * i;
		(g_sglist->info[i]).npages = g_feature_npages[feature_num];
		PRINT_INFO("%u, phys_addr:0x%llx\n", i, g_sglist->info[i].phys_addr);
	}
}

static int sub_rgn_cfg_test(u32 feature_num, u32 segment_num)
{
	u32 reg3_val, reg2_val;
	u32 reg3_val_expect, reg2_val_expect;

	if (segment_num == SEGMENT_NUM_1) {
		reg3_val_expect = SEGMENT_NUM_1_RGN_3;
		reg2_val_expect = SEGMENT_NUM_1_RGN_2;
	} else if (segment_num == SEGMENT_NUM_16) {
		reg3_val_expect = SEGMENT_NUM_16_RGN_3;
		reg2_val_expect = SEGMENT_NUM_16_RGN_2;
	}else if (segment_num == SEGMENT_NUM_32) {
		reg3_val_expect = SEGMENT_NUM_32_RGN_3;
		reg2_val_expect = SEGMENT_NUM_32_RGN_2;
	}else if (segment_num == SEGMENT_NUM_48) {
		reg3_val_expect = SEGMENT_NUM_48_RGN_3;
		reg2_val_expect = SEGMENT_NUM_48_RGN_2;
	}

	if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_SET_SEC) != OK) {
		PRINT_ERROR("DDR_SET_SEC fail!\n");
		return ERROR;
	}
	reg3_val = readl(SOC_DMSS_ASI_SEC_SUB_RGN3_ADDR(SOC_ACPU_DMSS_BASE_ADDR, SUB_RGN_NUM(g_sub_rgn_cfg_table[feature_num].region_num), CPU_ASI_NUM));
	reg2_val = readl(SOC_DMSS_ASI_SEC_SUB_RGN2_ADDR(SOC_ACPU_DMSS_BASE_ADDR, SUB_RGN_NUM(g_sub_rgn_cfg_table[feature_num].region_num), CPU_ASI_NUM));
	if (reg3_val != reg3_val_expect || reg2_val != reg2_val_expect) {
		PRINT_ERROR("DDR_SET_SEC reg3_val:0x%x, reg2_val:0x%x fail!\n", reg3_val, reg2_val);
		return ERROR;
	}
	if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_CHECK_SEC) != OK) {
		PRINT_ERROR("DDR_CHECK_SEC fail!\n");
		return ERROR;
	}
	if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_UNSET_SEC) != OK) {
		PRINT_ERROR("DDR_UNSET_SEC fail!\n");
		return ERROR;
	}
	reg3_val = readl(SOC_DMSS_ASI_SEC_SUB_RGN3_ADDR(SOC_ACPU_DMSS_BASE_ADDR, SUB_RGN_NUM(g_sub_rgn_cfg_table[feature_num].region_num), CPU_ASI_NUM));
	reg2_val = readl(SOC_DMSS_ASI_SEC_SUB_RGN2_ADDR(SOC_ACPU_DMSS_BASE_ADDR, SUB_RGN_NUM(g_sub_rgn_cfg_table[feature_num].region_num), CPU_ASI_NUM));
	if (reg3_val != SUB_RGN_INIT_VALUE || reg2_val != SUB_RGN_INIT_VALUE) {
		PRINT_ERROR("DDR_UNSET_SEC reg_val:0x%x, reg2_val:0x%x fail!\n", reg3_val, reg2_val);
		return ERROR;
	}
	if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_CHECK_UNSEC) != OK) {
		PRINT_ERROR("DDR_CHECK_UNSEC fail!\n");
		return ERROR;
	}

	return OK;
}

static int sub_rgn_test_base(u32 segment_num)
{
	u32 feature_num;

	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		sglist_init(feature_num, segment_num);

		if (sub_rgn_cfg_test(feature_num, segment_num) != OK) {
			PRINT_ERROR("[%s_feature_num:%u] fail\n", __func__, feature_num);
			return ERROR;
		}
	}

	return OK;
}

/*
 * sub_rgn_test_case001, select typical segment_num; x00431728; 2019/06/26
 */
static int sub_rgn_test_case001(void)
{
	u32 segment_num = SEGMENT_NUM_1;

	if (sub_rgn_test_base(segment_num) != OK) {
		goto error_proc;
	}
	segment_num = SEGMENT_NUM_16;
	if (sub_rgn_test_base(segment_num) != OK) {
		goto error_proc;
	}
	segment_num = SEGMENT_NUM_32;
	if (sub_rgn_test_base(segment_num) != OK) {
		goto error_proc;
	}
	segment_num = SEGMENT_NUM_48;
	if (sub_rgn_test_base(segment_num) != OK) {
		goto error_proc;
	}
	return OK;

error_proc:
	PRINT_ERROR("[%s] segment_num :0x%x fail\n", __func__, segment_num);
	return ERROR;
}

/*
 * wrong segment addr; x00431728; 2019/06/27
 */
static int sub_rgn_test_case002(void)
{
	u32 feature_num;

	g_sglist->infoLength = 0x2; /* can not 1 */

	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		/* segment start addr is less than cma start addr, config fail */
		g_sglist->info[0].phys_addr = g_sub_rgn_cfg_table[feature_num].start_addr - SUB_GRN_ZONE_1M;
		g_sglist->info[0].npages = g_feature_npages[feature_num];
		if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_SET_SEC) != ERROR) {

			PRINT_ERROR("[%s] fail!\n", __func__);
			return ERROR;
		}
		/* segment end addr is beyond cma end addr, config fail */
		g_sglist->info[0].phys_addr = g_sub_rgn_cfg_table[feature_num].start_addr;
		g_sglist->info[0].npages = g_feature_npages[feature_num] * (SUB_BIT_MAX_NUM + 1);
		if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_SET_SEC) != ERROR) {
			PRINT_ERROR("[%s] fail!\n", __func__);
			return ERROR;
		}
		/* segment start and end address is beyond cma end addr, config fail */
		g_sglist->info[0].phys_addr = g_sub_rgn_cfg_table[feature_num].start_addr + g_feature_npages[feature_num] * (SUB_BIT_MAX_NUM + 1);
		g_sglist->info[0].npages = g_feature_npages[feature_num] * (SUB_BIT_MAX_NUM + 1);
		if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_SET_SEC) != ERROR) {
			PRINT_ERROR("[%s] fail!\n", __func__);
			return ERROR;
		}
	}

	return OK;
}

/*
 * wrong segment size; x00431728; 2019/06/27
 */
static int sub_rgn_test_case003(void)
{
	u32 feature_num;

	g_sglist->infoLength = 0x1;

	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		g_sglist->info[0].phys_addr = g_sub_rgn_cfg_table[feature_num].start_addr;
		g_sglist->info[0].npages = g_feature_npages[feature_num] + PAGES_512K;
		if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_SET_SEC) != ERROR) {
			return ERROR;
		}
	}

	return OK;
}

/*
 * wrong infoLength; x00431728; 2019/04/03
 */
static int sub_rgn_test_case004(void)
{
	u32 feature_num;

	g_sglist->infoLength = SUB_BIT_MAX_NUM + 1;

	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		g_sglist->info[0].phys_addr = g_sub_rgn_cfg_table[feature_num].start_addr;
		g_sglist->info[0].npages = g_feature_npages[feature_num];
		if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_SET_SEC) != ERROR) {
			return ERROR;
		}
	}

	return OK;
}

/*
 * segment overlap; x00431728; 2019/04/03
 */
static int sub_rgn_test_case005(void)
{
	u32 feature_num;

	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		g_sglist->infoLength = 0x2;
		g_sglist->info[0].phys_addr = g_sub_rgn_cfg_table[feature_num].start_addr;
		g_sglist->info[0].npages = g_feature_npages[feature_num];
		g_sglist->info[1].phys_addr = g_sub_rgn_cfg_table[feature_num].start_addr;
		g_sglist->info[1].npages = g_feature_npages[feature_num];
		if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_SET_SEC) != ERROR) {
			PRINT_ERROR("[%s] fail\n", __func__);
			return ERROR;
		}
		g_sglist->infoLength = 0x1;
		if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_UNSET_SEC) != OK) {
			PRINT_ERROR("[%s] fail\n", __func__);
			return ERROR;
		}
	}



	return OK;
}

/*
 * different granularity_size, config and release alternately; x00431728; 2019/04/03
 */
static u32 get_feature_num_by_gran(u32 granularity_size)
{
	u32 feature_num;
	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		if (g_sub_rgn_cfg_table[feature_num].granularity_size == granularity_size) {
			return feature_num;
		}
	}
	return SUB_RGN_FEATURE_MAX;
}
static int sub_rgn_test_case006(void)
{
	u32 feature_num_1, feature_num_2;

	feature_num_1 = get_feature_num_by_gran(SUB_GRN_ZONE_1M);
	feature_num_2 = get_feature_num_by_gran(SUB_GRN_ZONE_2M);

	sglist_init(feature_num_1, 0x1);
	if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num_1].sec_feature, DDR_SET_SEC) != OK) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}
	sglist_init(feature_num_2, 0x1);
	if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num_2].sec_feature, DDR_SET_SEC) != OK) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}
	sglist_init(feature_num_1, 0x1);
	if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num_1].sec_feature, DDR_UNSET_SEC) != OK) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}
	sglist_init(feature_num_2, 0x1);
	if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num_2].sec_feature, DDR_UNSET_SEC) != OK) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}

	return OK;
}

/*
 * normal_rgn_test begin; x00431728; 2019/04/03
 */
static int normal_rgn_test_base(u32 feature_num, u32 segment_num, u32 start_addr, u32 npages)
{
	u32 reg_map0_val, reg_map1_val;

	g_sglist->infoLength = segment_num;
	g_sglist->info[0].phys_addr = start_addr;
	g_sglist->info[0].npages = npages;

	if (ddr_sec_cfg(g_sglist, g_normal_rgn_cfg_table[feature_num].sec_feature, DDR_SET_SEC) != OK) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}
	reg_map0_val = readl(SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, g_normal_rgn_cfg_table[feature_num].region_num, CPU_ASI_NUM));
	reg_map1_val = readl(SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(SOC_ACPU_DMSS_BASE_ADDR, g_normal_rgn_cfg_table[feature_num].region_num, CPU_ASI_NUM));
	if (reg_map0_val != NORMAL_REGION_MAP0_VALUE || reg_map1_val != NORMAL_REGION_MAP1_VALUE) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}
	if (ddr_sec_cfg(g_sglist, g_normal_rgn_cfg_table[feature_num].sec_feature, DDR_UNSET_SEC) != OK) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}
	reg_map0_val = readl(SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, g_normal_rgn_cfg_table[feature_num].region_num, CPU_ASI_NUM));
	reg_map1_val = readl(SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(SOC_ACPU_DMSS_BASE_ADDR, g_normal_rgn_cfg_table[feature_num].region_num, CPU_ASI_NUM));
	if (reg_map0_val != NORMAL_REGION_INIT_VALUE || reg_map1_val != NORMAL_REGION_INIT_VALUE) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}

	return OK;
}

/*
 * typical cfg test; x00431728; 2019/04/03
 */
static int normal_rgn_test001(void)
{
	u32 feature_num;

	for (feature_num = 0; feature_num < NORMAL_RGN_MAX_NUM; feature_num++) {
		if (normal_rgn_test_base(feature_num, 0x1, NORMAL_REGION_START_ADDR, PAGES_64K) != OK) {
			return ERROR;
		}
	}
	return OK;
}

/*
 * wrong infoLength; x00431728; 2019/04/03
 */
static int normal_rgn_test002(void)
{
	if (normal_rgn_test_base(0x0, 0x2, NORMAL_REGION_START_ADDR, PAGES_64K) != ERROR) {
		return ERROR;
	}
	return OK;
}

/*
 * segment addr is not integer multiple of 64KB(0x10000); x00431728; 2019/04/03
 */
static int normal_rgn_test003(void)
{
	if (normal_rgn_test_base(0x0, 0x1, (NORMAL_REGION_START_ADDR + PAGES_8K), PAGES_64K) != ERROR) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}
	if (normal_rgn_test_base(0x0, 0x1, NORMAL_REGION_START_ADDR, (PAGES_64K + PAGES_8K)) != ERROR) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}
	return OK;
}

/*
 * cfg addr overlap; x00431728; 2019/04/03
 */
static int normal_rgn_test004(void)
{
	u32 feature_num = 0;

	g_sglist->infoLength = 0x1;
	g_sglist->info[0].phys_addr = NORMAL_REGION_START_ADDR;
	g_sglist->info[0].npages = PAGES_64K;

	if (ddr_sec_cfg(g_sglist, g_normal_rgn_cfg_table[feature_num].sec_feature, DDR_SET_SEC) != OK) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}

	if (ddr_sec_cfg(g_sglist, g_normal_rgn_cfg_table[feature_num + 1].sec_feature, DDR_SET_SEC) != ERROR) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}

	if (ddr_sec_cfg(g_sglist, g_normal_rgn_cfg_table[feature_num].sec_feature, DDR_UNSET_SEC) != OK) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}
	return OK;
}

static int check_sglist_pid_test(void)
{
	u32 feature_num;

	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		sglist_init(feature_num, SEGMENT_NUM_16);

		if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_SET_SEC) != OK) {
			PRINT_ERROR("[%s] fail\n", __func__);
			return ERROR;
		}
		if (check_sglist_pid(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature) != OK) {
			PRINT_ERROR("[%s] fail\n", __func__);
			return ERROR;
		}
		if (ddr_sec_cfg(g_sglist, g_sub_rgn_cfg_table[feature_num].sec_feature, DDR_UNSET_SEC) != OK) {
			PRINT_ERROR("[%s] fail\n", __func__);
			return ERROR;
		}
	}

	return OK;
}

static int check_unsec_sglist_test(void)
{
	g_sglist->infoLength = 0x1;
	g_sglist->info[0].phys_addr = LPMCU_START_ADDR;
	g_sglist->info[0].npages = PAGES_64K;

	if (check_unsec_sglist(g_sglist) != ERROR) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}

	g_sglist->info[0].phys_addr = NORMAL_REGION_START_ADDR;
	g_sglist->info[0].npages = PAGES_64K;

	if (check_unsec_sglist(g_sglist) != OK) {
		PRINT_ERROR("[%s] fail\n", __func__);
		return ERROR;
	}

	return OK;
}

struct test g_tests[] = {
	{ "sub_rgn_test_case001", sub_rgn_test_case001 },
	{ "sub_rgn_test_case002", sub_rgn_test_case002 },
	{ "sub_rgn_test_case003", sub_rgn_test_case003 },
	{ "sub_rgn_test_case004", sub_rgn_test_case004 },
	{ "sub_rgn_test_case005", sub_rgn_test_case005 },
	{ "sub_rgn_test_case006", sub_rgn_test_case006 },
	{ "normal_rgn_test001", normal_rgn_test001 },
	{ "normal_rgn_test002", normal_rgn_test002 },
	{ "normal_rgn_test003", normal_rgn_test003 },
	{ "normal_rgn_test004", normal_rgn_test004 },
	{ "check_sglist_pid_test", check_sglist_pid_test },
	{ "check_unsec_sglist_test", check_unsec_sglist_test },
};

//#error "CONFIG_HISI_SEC_DDR_TEST" /* delete it when you use */
int sec_region_test(void)
{
	int i, ret;
	int error_flag = 0;
	u32 feature_num;
	struct test *myTest = &(g_tests[0]);

	g_sglist = (struct sglist *)malloc(sizeof(struct sglist) + sizeof(TEE_PAGEINFO) * 2);
	/* granularity_size transform into pages */
	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		if (g_sub_rgn_cfg_table[feature_num].granularity_size == SUB_GRN_ZONE_1M) {
			g_feature_npages[feature_num] = PAGES_1M;
		} else if (g_sub_rgn_cfg_table[feature_num].granularity_size == SUB_GRN_ZONE_2M) {
			g_feature_npages[feature_num] = PAGES_2M;
		}
	}

	for (i = 0;i < sizeof(g_tests)/sizeof(struct test); i++) {
		ret = myTest[i].func();
		if (ret == OK) {
			PRINT_ERROR("[%s] pass\n", myTest[i].name);
		} else {
			PRINT_ERROR("[%s] fail\n", myTest[i].name);
			error_flag = 1;
		}
	}
	PRINT_ERROR("[%s] error_flag:%d\n", __func__, error_flag);
	free(g_sglist);
	g_sglist = NULL;

	if (error_flag != 0) {
		return ERROR;
	}
	return OK;
}

