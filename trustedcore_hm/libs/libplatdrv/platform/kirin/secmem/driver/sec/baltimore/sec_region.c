/*
 * Copyright @ Huawei Technologies Co., Ltd. 2019-2028. All rights reserved.
 * Description: secure region function of the secure os
 * Author: x00431728
 * Create: 2019-06-20
 */

#include "sec_region.h"
#include <tzmp2_ops.h>
#include <sec_region_ops.h>
#include <sec_common.h>
#include <soc_acpu_baseaddr_interface.h>
#include <ddr_sec_feature.h>
#include <ddr_define.h>
#include <soc_dmss_interface.h>
#include <soc_mid.h>
#include "sre_syscall.h"
#include "sre_task.h"
#include <procmgr_ext.h>
#include "tee_log.h"
#include "mem_page_ops.h"
#include <stdint.h>
#include <pthread.h>
#include <mem_ops_ext.h> // get_cs_es_info
#include <dynion.h> // TEE_PAGEINFO
#include <register_ops.h> // readl
#include "securec.h"
#include "drv_pal.h"
#include <sion_recycling.h>

#ifdef CONFIG_HISI_SEC_DDR_TEST
#include "sec_region_test.h"
#endif

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
#include <hisi_ddr_autofsgt_proxy.h>
#endif

static unsigned int g_rgn_num[ASI_NUM_MAX];
#ifdef CONFIG_HISI_DDR_SEC_HIFI_RESET
static SEC_RGN_CFG g_hifi_reset_sec_rgn = { 0 };
#endif
pthread_mutex_t g_sec_pthread_lock = PTHREAD_MUTEX_INITIALIZER;
TEE_UUID g_sec_uuid[] = { HIAI_TINY_UUID, TUI_UUID, SEC_ISP_UUID, SEC_FACE_UUID,
			SECBOOT_UUID, EID1_UUID, EID3_UUID, ION_UUID, VLTMM_UUID, GTASK_UUID, SEC_IVP_UUID,
			SEC_FACE3D_AE_AC_UUID };
TEE_UUID g_cur_uuid = UUID_INITIALIZER;
u32 g_uuid_get_flag = UUID_NOT_GET;

SUB_RGN_CFG g_sub_rgn_cfg_table[SUB_RGN_FEATURE_MAX] = {
	{
		/* DDR_SEC_TINY */
		.sec_feature = DDR_SEC_TINY,
		.region_num = TINY_RGN_NUM,
		.start_addr = 0x0,
		.end_addr = 0x0,
		.granularity_size = 0x0,
	},
	{
		/* DDR_SEC_TUI */
		.sec_feature = DDR_SEC_TUI,
		.region_num = TUI_RGN_NUM,
		.start_addr = 0x0,
		.end_addr = 0x0,
		.granularity_size = 0x0,
	},
	{
		/* DDR_SEC_FACE */
		.sec_feature = DDR_SEC_FACE,
		.region_num = FACE_RGN_NUM_3,
		.start_addr = 0x0,
		.end_addr = 0x0,
		.granularity_size = 0x0,
	},
	{
		/* DDR_SEC_FACE */
		.sec_feature = DDR_SEC_FACE,
		.region_num = FACE_RGN_NUM_4,
		.start_addr = 0x0,
		.end_addr = 0x0,
		.granularity_size = 0x0,
	},
	{
		/* DDR_SEC_ID */
		.sec_feature = DDR_SEC_EID,
		.region_num = EID_RGN_NUM,
		.start_addr = 0x0,
		.end_addr = 0x0,
		.granularity_size = 0x0,
	},
};

/* check the sec number and region number */
#define MDDRC_SEC_CHECK_SECANDRGN(ret, asi_num, rgn_num) \
	do { \
		if (asi_num >= ASI_NUM_MAX) { \
			PRINT_ERROR("[%s]_%d: sec num %d is invalid\n", __func__, __LINE__, asi_num); \
			ret = ERROR; \
		} \
		else { \
			if (rgn_num >= g_rgn_num[asi_num]) { \
				PRINT_ERROR("[%s]_%d: region %d not in scope :[0-%d]\n", \
				__func__, __LINE__, rgn_num, g_rgn_num[asi_num] - 1); \
				ret = ERROR; \
			} \
		} \
	} while (0)

#define CHECK_RET(ret) \
	do { \
		if (ret != OK) { \
			goto err_proc; \
		} \
	} while (0)

static unsigned int get_rgn_num_max(unsigned int asi_num)
{
	SOC_DMSS_ASI_RTL_INF2_UNION asi_rtl_inf2;

	asi_rtl_inf2.value = readl((u32)SOC_DMSS_ASI_RTL_INF2_ADDR(SOC_ACPU_DMSS_BASE_ADDR, asi_num));
	return asi_rtl_inf2.reg.rtl_sec_rgn_num;
}

static int check_rgn_usable(unsigned int asi_num, unsigned int rgn_num)
{
	int ret = OK;
	unsigned int value;

	MDDRC_SEC_CHECK_SECANDRGN(ret, asi_num, rgn_num);

	value = readl(SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
	if (((value >> SOC_DMSS_ASI_SEC_RGN_MAP0_rgn_en_START) & 0x1) != 0) {
		PRINT_DEBUG("map0:0x%x, map1:0x%x, wr:0x%x, rd:0x%x\n",
			readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num)),
			readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num)),
			readl((u32)SOC_DMSS_ASI_SEC_MID_WR_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num)),
			readl((u32)SOC_DMSS_ASI_SEC_MID_RD_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num)));
		ret = ERROR;
	}

	return ret;
}

/* one region */
static int sec_region_cfg(unsigned int asi_num, unsigned int rgn_num, const SEC_RGN_CFG *sec_rgn_cfg)
{
	int ret;
	volatile SOC_DMSS_ASI_SEC_RGN_MAP0_UNION *sec_rgn_map0 = NULL;
	volatile SOC_DMSS_ASI_SEC_RGN_MAP1_UNION *sec_rgn_map1 = NULL;
	volatile SOC_DMSS_ASI_SEC_MID_WR_UNION *sec_mid_wr = NULL;
	volatile SOC_DMSS_ASI_SEC_MID_RD_UNION *sec_mid_rd = NULL;

	ret = check_rgn_usable(asi_num, rgn_num);

	if (ret != OK || sec_rgn_cfg == NULL) {
		PRINT_ERROR("[%s]_%d: asi%x rgn%x cfg err!\n", __func__, __LINE__, asi_num, rgn_num);
		return ERROR;
	}

	if ((sec_rgn_cfg->start_addr & SEC_RGN_ADDR_MASK) != 0 || (sec_rgn_cfg->end_addr & SEC_RGN_ADDR_MASK) != 0) {
		PRINT_ERROR("[%s]_%d: err!\n", __func__, __LINE__);
		PRINT_DEBUG("[%s]_%d: asi%x rgn%x addr err! start:0x%llx,end0x%llx;\n", __func__, __LINE__, asi_num, rgn_num,
			sec_rgn_cfg->start_addr, sec_rgn_cfg->end_addr);
		return ERROR;
	}

	sec_rgn_map0 = (volatile SOC_DMSS_ASI_SEC_RGN_MAP0_UNION *)
		((unsigned long)SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
	sec_rgn_map1 = (volatile SOC_DMSS_ASI_SEC_RGN_MAP1_UNION *)
		((unsigned long)SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
	sec_mid_wr = (volatile SOC_DMSS_ASI_SEC_MID_WR_UNION *)
		((unsigned long)SOC_DMSS_ASI_SEC_MID_WR_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
	sec_mid_rd = (volatile SOC_DMSS_ASI_SEC_MID_RD_UNION *)
		((unsigned long)SOC_DMSS_ASI_SEC_MID_RD_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));

	sec_rgn_map0->reg.rgn_en = 0;

	sec_rgn_map0->reg.rgn_base_addr = ((~(SEC_RGN_ADDR_MASK)) & sec_rgn_cfg->start_addr) >> DDR_SEC_GRANULARITY;
	sec_rgn_map1->reg.rgn_top_addr = ((~(SEC_RGN_ADDR_MASK)) & (sec_rgn_cfg->end_addr - 1)) >> DDR_SEC_GRANULARITY;
	sec_rgn_map1->reg.sp = sec_rgn_cfg->attri;
	sec_mid_wr->value = sec_rgn_cfg->mid_wr;
	sec_mid_rd->value = sec_rgn_cfg->mid_rd;
	sec_rgn_map0->reg.rgn_en = sec_rgn_cfg->rgn_en;

	return OK;
}

static inline void sec_region_clean(unsigned int asi_num, unsigned int rgn_num)
{
	unsigned int value;

	value = readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
	writel((~(1UL << SOC_DMSS_ASI_SEC_RGN_MAP0_rgn_en_START)) & value,
		SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));

	writel(ALL_MID, SOC_DMSS_ASI_SEC_MID_WR_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
	writel(ALL_MID, SOC_DMSS_ASI_SEC_MID_RD_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
	writel(0, SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
	writel(0, SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
}

static int sec_region_cfg_mask(unsigned int asi_mask, unsigned int reserved_reg, const SEC_RGN_CFG *sec_rgn_cfg)
{
	unsigned int set_asi, clean_asi;
	int ret = OK;

	if (sec_rgn_cfg == NULL) {
		PRINT_ERROR("[%s]_%d: sec_rgn_cfg is NULL!\n", __func__, __LINE__);
		return ERROR;
	}

	for (set_asi = 0; set_asi < ASI_NUM_MAX; set_asi++) {
		if ((BIT(set_asi) & asi_mask) != 0) {
			ret = sec_region_cfg(set_asi, reserved_reg, sec_rgn_cfg);
			if (ret != OK) {
				PRINT_ERROR("sec_region_cfg fail\n");
				break;
			}
		}
	}

	/* if set sec region error */
	for (clean_asi = 0; (ret != OK) && (clean_asi < set_asi); clean_asi++) {
		if ((BIT(clean_asi) & asi_mask) != 0) {
			sec_region_clean(clean_asi, reserved_reg);
		}
	}

	return ret;
}

static int is_not_covered_by_normal_region(u64 start_addr, u64 end_addr)
{
	unsigned int asi_num, rgn_num;
	SOC_DMSS_ASI_SEC_RGN_MAP0_UNION rgn_map0;
	SOC_DMSS_ASI_SEC_RGN_MAP1_UNION rgn_map1;
	unsigned long long rgn_start, rgn_end;

	if (start_addr >= end_addr) {
		return ERROR;
	}

	for (asi_num = 0; asi_num < ASI_NUM_MAX; asi_num++) {
		if ((BIT(asi_num) & DDR_SEC_ALL_ASI_MASK) == 0) {
			continue;
		}
		for (rgn_num = 1 + SUB_RGN_USED; rgn_num < g_rgn_num[asi_num]; rgn_num++) {
			rgn_map0.value = readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
			if (rgn_map0.reg.rgn_en == 0) {
				continue;
			}
			rgn_map1.value = readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
			rgn_start = (u64)(rgn_map0.reg.rgn_base_addr) << DDR_SEC_GRANULARITY;
			rgn_end = (((u64)(rgn_map1.reg.rgn_top_addr) << DDR_SEC_GRANULARITY) | SEC_RGN_ADDR_MASK) + 0x1;
			/* rgn_start~rgn_end */
			if ((start_addr >= rgn_start && start_addr < rgn_end) ||
				(end_addr > rgn_start && end_addr <= rgn_end) ||
				(rgn_start < rgn_end && start_addr <= rgn_start && end_addr >= rgn_end)) {
				PRINT_ERROR("is covered by region\n");
				PRINT_DEBUG("a_n%d, r_n%d, 0x%x, 0x%x\n", asi_num, rgn_num, rgn_map0.value, rgn_map1.value);
				return ERROR; /* is covered by region */
			}
		}
	}

	return OK; /*is not covered by region*/
}

#ifdef CONFIG_HISI_DDR_SEC_HIFI_RESET
static int ddr_sec_cfg_for_hifi_reset(u64 start_addr, u64 end_addr)
{
	int ret;
	SEC_RGN_CFG cfg_data;

	if (g_hifi_reset_sec_rgn.rgn_en != 0) {
		PRINT_ERROR("hifi reset region has been set!\n");
		return ERROR;
	}

	PRINT_INFO("ddr_sec_cfg_for_hifi_reset:start 0x%llx, end 0x%llx\n", start_addr, end_addr);

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_HIFI_SET, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	if (is_not_covered_by_normal_region(start_addr, end_addr) == ERROR) {
		PRINT_ERROR("hifi reset addr has been covered!\n");
		return ERROR;
	}

	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;

	/* port modem vdec_ivp isp_dss npu gpu forbid */
	cfg_data.mid_rd = FORBID_MID;
	cfg_data.mid_wr = FORBID_MID;
	cfg_data.attri = RW_FORBID;
	ret = sec_region_cfg_mask(MODEM_ASI_MASK | VDEC_IVP_ASI_MASK | ISP_DSS_ASI_MASK | NPU_ASI_MASK | GPU_ASI_MASK, HIFI_REBOOT_RGN_NUM, &cfg_data);
	CHECK_RET(ret);

	/* port CPU SW\SR */
	cfg_data.mid_rd = CPU_ALL;
	cfg_data.mid_wr = CPU_ALL;
	cfg_data.attri = SEC_WR | SEC_RD;
	ret = sec_region_cfg_mask(CPU_ASI_MASK, HIFI_REBOOT_RGN_NUM, &cfg_data);
	CHECK_RET(ret);

	/* port subsys SW\SR */
	cfg_data.mid_rd = BIT(CC712_MID);
	cfg_data.mid_wr = BIT(CC712_MID);
	cfg_data.attri = SEC_WR | SEC_RD;
	ret = sec_region_cfg_mask(SUBSYS_ASI_MASK, HIFI_REBOOT_RGN_NUM, &cfg_data);
	CHECK_RET(ret);

	g_hifi_reset_sec_rgn.rgn_en = 1;
	g_hifi_reset_sec_rgn.start_addr = start_addr;
	g_hifi_reset_sec_rgn.end_addr = end_addr;

err_proc:

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_HIFI_SET, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return ret;
}

static int ddr_sec_clean_for_hifi_reset(u64 start_addr, u64 end_addr)
{
	unsigned int i;

	if (g_hifi_reset_sec_rgn.rgn_en == 0) {
		PRINT_ERROR("hifi reset region has not been set!\n");
		return ERROR;
	}

	PRINT_INFO("ddr_sec_clean_for_hifi_reset:start 0x%llx, end 0x%llx\n", start_addr, end_addr);

	if (start_addr != g_hifi_reset_sec_rgn.start_addr || end_addr != g_hifi_reset_sec_rgn.end_addr) {
		PRINT_ERROR("hifi reset addr error!\n");
		return ERROR;
	}

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_HIFI_CLEAN, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	/* clean sec region */
	for (i = 0; i < ASI_NUM_MAX; i++) {
		sec_region_clean(i, HIFI_REBOOT_RGN_NUM);
	}

	g_hifi_reset_sec_rgn.rgn_en = 0;
	g_hifi_reset_sec_rgn.start_addr = 0;
	g_hifi_reset_sec_rgn.end_addr = 0;

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_HIFI_CLEAN, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return OK;
}
#endif

int ddr_sec_cfg_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id)
{
	int ret = ERROR;

	if (pthread_mutex_lock(&g_sec_pthread_lock) != OK) {
		PRINT_ERROR("cfg:Wait lock_flag failed!\n");
		return ret;
	}

	switch (feature_id) {
#ifdef CONFIG_HISI_DDR_SEC_HIFI_RESET
		case DDR_SEC_HIFI_RESET:
			ret = ddr_sec_cfg_for_hifi_reset(start_addr, end_addr);
			break;
#endif
		default:
			PRINT_ERROR("ddr_sec_cfg:error feature!\n");
			break;
	}

	if (pthread_mutex_unlock(&g_sec_pthread_lock) != OK) {
		ret = ERROR;
		PRINT_ERROR("cfg:Release lock_flag failed!\n");
	}
	return ret;
}

#ifdef CONFIG_SOC_WE_WORKAROUND
int __ddr_sec_clean_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id)
#else
int ddr_sec_clean_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id)
#endif
{
	int ret = ERROR;

	if (pthread_mutex_lock(&g_sec_pthread_lock) != OK) {
		PRINT_ERROR("clean:Wait lock_flag failed!\n");
		return ret;
	}

	switch (feature_id) {
#ifdef CONFIG_HISI_DDR_SEC_HIFI_RESET
		case DDR_SEC_HIFI_RESET:
			ret = ddr_sec_clean_for_hifi_reset(start_addr, end_addr);
			break;
#endif
		default:
			PRINT_ERROR("ddr_sec_clean:error feature!\n");
			break;
	}

	if (pthread_mutex_unlock(&g_sec_pthread_lock) != OK) {
		ret = ERROR;
		PRINT_ERROR("clean:Release lock_flag failed!\n");
	}
	return ret;
}

int ddr_sec_check_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id)
{
	(void)start_addr;
	(void)end_addr;

	PRINT_ERROR("[%s_%d]:error feature(%d)!\n", __func__, __LINE__, feature_id);
	return ERROR;
}

/* SUB_RGN_CFG */
static u32 get_sub_rgn_value(u32 asi_num, u32 rgn_num, u32 sub_rgn_num)
{
	u32 reg_value = 0;

	switch (sub_rgn_num) {
		case SUB_BIT_RGN_NUM_0:
			reg_value = readl(SOC_DMSS_ASI_SEC_SUB_RGN0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
			break;
		case SUB_BIT_RGN_NUM_1:
			reg_value = readl(SOC_DMSS_ASI_SEC_SUB_RGN1_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
			break;
		case SUB_BIT_RGN_NUM_2:
			reg_value = readl(SOC_DMSS_ASI_SEC_SUB_RGN2_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
			break;
		case SUB_BIT_RGN_NUM_3:
			reg_value = readl(SOC_DMSS_ASI_SEC_SUB_RGN3_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
			break;
		default:
			PRINT_ERROR("sub_rgn_num is wrong\n");
			break;
	}
	return reg_value;
}

static void set_sub_rgn_value(u32 reg_value, u32 asi_num, u32 rgn_num, u32 sub_rgn_num)
{
	switch (sub_rgn_num) {
		case SUB_BIT_RGN_NUM_0:
			writel(reg_value, SOC_DMSS_ASI_SEC_SUB_RGN0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
			break;
		case SUB_BIT_RGN_NUM_1:
			writel(reg_value, SOC_DMSS_ASI_SEC_SUB_RGN1_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
			break;
		case SUB_BIT_RGN_NUM_2:
			writel(reg_value, SOC_DMSS_ASI_SEC_SUB_RGN2_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
			break;
		case SUB_BIT_RGN_NUM_3:
			writel(reg_value, SOC_DMSS_ASI_SEC_SUB_RGN3_ADDR(SOC_ACPU_DMSS_BASE_ADDR, rgn_num, asi_num));
			break;
		default:
			PRINT_ERROR("wrong sub_rgn_num\n");
			break;
	}
}

static int sub_rgn_cfg_asi(SUB_RGN_CFG *sub_pro_cfg,
				DDR_CFG_TYPE ddr_cfg_type,
				u32 sub_rgn_num,
				u32 sub_bit_length_reg,
				u32 sub_rgn_start_bit)
{
	u32 asi_num, reg_value, reg_value_check;

	for (asi_num = 0; asi_num < ASI_NUM_MAX; asi_num++) {
		if (ASI_NUM_BYPASS(asi_num)) {
			continue;
		}
		reg_value = get_sub_rgn_value(asi_num, SUB_RGN_NUM(sub_pro_cfg->region_num), sub_rgn_num);
		switch (ddr_cfg_type) {
			case DDR_SET_SEC:
				reg_value &= ~(VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(sub_bit_length_reg), sub_rgn_start_bit));
				set_sub_rgn_value(reg_value, asi_num, SUB_RGN_NUM(sub_pro_cfg->region_num), sub_rgn_num);
				break;
			case DDR_UNSET_SEC:
				reg_value |= VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(sub_bit_length_reg), sub_rgn_start_bit);
				set_sub_rgn_value(reg_value, asi_num, SUB_RGN_NUM(sub_pro_cfg->region_num), sub_rgn_num);
				break;
			case DDR_CHECK_SEC:
				reg_value_check = reg_value & VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(sub_bit_length_reg), sub_rgn_start_bit);
				/* 0 is sec */
				if (reg_value_check != 0) {
					PRINT_ERROR("[DDR_CHECK_SEC]reg_value 0x%x, reg_value_temp 0x%x\n", reg_value, reg_value_check);
					return ERROR;
				}
				break;
			case DDR_CHECK_UNSEC:
				/* all 1 is unsec */
				reg_value_check = reg_value & VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(sub_bit_length_reg), sub_rgn_start_bit);
				if (reg_value_check != VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(sub_bit_length_reg), sub_rgn_start_bit)) {
					PRINT_ERROR("[DDR_CHECK_UNSEC]reg_value 0x%x, reg_value_check 0x%x\n", reg_value, reg_value_check);
					return ERROR;
				}
				break;
			default:
				PRINT_ERROR("wrong ddr_cfg_type :%d\n", ddr_cfg_type);
				return ERROR;
		}
	}

	return OK;
}

static int sub_rgn_cfg(SUB_RGN_CFG *sub_pro_cfg, u32 sub_rgn_cfg_addr, u32 sub_rgn_cfg_size, DDR_CFG_TYPE ddr_cfg_type)
{
	int loop_flag;
	u32 sub_rgn_num, sub_rgn_start_bit, sub_bit_length_total, sub_bit_length_reg;

	/* sub_rgn need cfg from sub_rgn3 to sub_rgn0 */
	sub_rgn_num = SUB_BIT_RGN_NUM_MAX - sub_rgn_cfg_addr / ((sub_pro_cfg->granularity_size) * REG_BIT_NUM);
	sub_rgn_start_bit = (sub_rgn_cfg_addr / (sub_pro_cfg->granularity_size)) % REG_BIT_NUM;
	sub_bit_length_total = sub_rgn_cfg_size / (sub_pro_cfg->granularity_size);

	if (ddr_cfg_type == DDR_CHECK_SEC) { /* if size is not align, check bit add 1 */
		if (sub_rgn_cfg_size % sub_pro_cfg->granularity_size != 0) {
			sub_bit_length_total++;
		}
	}

	/* when the granularity_size of feature is cfg as 2M, the feature which is checked is 1M, then sub_bit_length_total need add 1 */
	if (ddr_cfg_type == DDR_CHECK_UNSEC && (sub_rgn_cfg_size % sub_pro_cfg->granularity_size != 0)) {
		PRINT_INFO("sub_rgn_cfg_size:0x%x, granularity_size: 0x%x\n", sub_rgn_cfg_size, sub_pro_cfg->granularity_size);
		sub_bit_length_total++;
	}

	PRINT_INFO("ddr_cfg_type is %d\n", ddr_cfg_type);

	do {
		if (sub_rgn_num > SUB_BIT_RGN_NUM_MAX) {
			PRINT_ERROR("wrong sub_rgn_num :%u,\n", sub_rgn_num);
			PRINT_DEBUG("sub_rgn_cfg_addr:0x%x\n", sub_rgn_cfg_addr);
			return ERROR;
		}
		loop_flag = 0;
		if ((sub_rgn_start_bit + sub_bit_length_total) > REG_BIT_NUM) {
			sub_bit_length_reg = REG_BIT_NUM - sub_rgn_start_bit;
			loop_flag = 1;
		} else {
			sub_bit_length_reg = sub_bit_length_total;
		}
		PRINT_INFO("sub_rgn_num: %u, sub_rgn_start_bit: %u, sub_bit_length_total: %u\n", sub_rgn_num, sub_rgn_start_bit, sub_bit_length_total);
		if (sub_rgn_cfg_asi(sub_pro_cfg, ddr_cfg_type, sub_rgn_num, sub_bit_length_reg, sub_rgn_start_bit) != OK) {
			return ERROR;
		}

		if (loop_flag) {
			sub_rgn_num--;
			sub_rgn_start_bit = 0;
			sub_bit_length_total -= sub_bit_length_reg;
		}
	} while (loop_flag);

	return OK;
}

static int check_segment(TEE_PAGEINFO *segment_info)
{
	u32 ret;
	u32 feature_num;
	u32 segment_cfg_addr;
	u64 segment_start_addr, feature_start_addr, feature_end_addr;

	segment_start_addr = segment_info->phys_addr;

	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		feature_start_addr = g_sub_rgn_cfg_table[feature_num].start_addr;
		feature_end_addr = g_sub_rgn_cfg_table[feature_num].end_addr;
		if (segment_start_addr >= feature_start_addr && segment_start_addr < feature_end_addr) {
			segment_cfg_addr = (u32)(segment_start_addr - feature_start_addr);
			PRINT_INFO("[check_segment] check feature:%u\n", feature_num);
			ret = sub_rgn_cfg(&(g_sub_rgn_cfg_table[feature_num]), segment_cfg_addr, segment_info->npages * PAGE_SIZE, DDR_CHECK_UNSEC);
			if (ret != OK) {
				return ERROR;
			}
		}
	}

	return OK;
}

static int is_not_covered_by_cma_region(u64 start_addr, u64 end_addr)
{
	if ((start_addr >= HISI_CMA_START && end_addr <= HISI_CMA_END) ||
		(start_addr >= FACE_CMA_START && end_addr <= FACE_CMA_END) ||
		(start_addr >= TINY_CMA_START && end_addr <= TINY_CMA_END) ||
		(start_addr >= SMEM_CMA_START && end_addr <= SMEM_CMA_END)) {
		return ERROR;
	}
	return OK;
}

static int check_sglist(struct sglist *sglist, u32 feature_num, DDR_CFG_TYPE ddr_cfg_type)
{
	TEE_PAGEINFO *segment_info = NULL;
	u32 segment_num;
	u64 segment_size;
	u64 segment_start_addr, segment_end_addr;

	for (segment_num = 0; segment_num < (sglist->infoLength); segment_num++) {
		segment_info = (TEE_PAGEINFO *)(sglist->info + segment_num); /* add segment_num to get segment_num addr */
		segment_start_addr = segment_info->phys_addr;
		segment_size = (u64)segment_info->npages * PAGE_SIZE;
		segment_end_addr = segment_start_addr + segment_size;
		if (ddr_cfg_type != DDR_CHECK_SEC) { /* addr may not align */
			if (segment_size % g_sub_rgn_cfg_table[feature_num].granularity_size != 0) {
				PRINT_ERROR("size is not align\n");
				PRINT_DEBUG("wrong segment_size:0x%llx, npages %u, PAGE_SIZE 0x%x\n",
				            segment_size, segment_info->npages, PAGE_SIZE);
				return ERROR;
			}
		}
		if (is_not_covered_by_cma_region(segment_start_addr, segment_end_addr) == OK) {
			PRINT_ERROR("is_not_covered_by_cma_region\n");
			PRINT_DEBUG("segment_start:0x%llx, segment_end:0x%llx\n", segment_start_addr, segment_end_addr);
			return ERROR;
		}
	}

	return OK;
}

static int cmp_uuid(TEE_UUID *uuid1, TEE_UUID *uuid2)
{
	if (memcmp(uuid1, uuid2, sizeof(TEE_UUID)) != OK) {
		return ERROR;
	}
	return OK;
}

static bool sec_face_check_uuid_fail(void)
{
	return (cmp_uuid(&g_cur_uuid, &g_sec_uuid[SEC_ISP_UUID_NUM]) != OK &&
		cmp_uuid(&g_cur_uuid, &g_sec_uuid[SEC_IVP_UUID_NUM]) != OK &&
		cmp_uuid(&g_cur_uuid, &g_sec_uuid[SEC_FACE_UUID_NUM]) != OK &&
		cmp_uuid(&g_cur_uuid, &g_sec_uuid[SECBOOT_UUID_NUM]) != OK &&
		cmp_uuid(&g_cur_uuid, &g_sec_uuid[VLTMM_UUID_NUM]) != OK &&
		cmp_uuid(&g_cur_uuid, &g_sec_uuid[GTASK_UUID_NUM]) != OK &&
		cmp_uuid(&g_cur_uuid,
			&g_sec_uuid[SEC_FACE3D_AE_AC_UUID_NUM]) != OK &&
		cmp_uuid(&g_cur_uuid, &g_sec_uuid[EID1_UUID_NUM]) != OK &&
		cmp_uuid(&g_cur_uuid, &g_sec_uuid[EID3_UUID_NUM]) != OK);
}

static int check_uuid(int feature_id)
{
	int ret = OK;
	u32 task_id = 0x0;
	int pid;
	spawn_uuid_t spawn_uuid = { 0 };

#ifdef CONFIG_HISI_SEC_DDR_TEST
	return OK;
#endif

#if defined(SECMEM_UT) && defined(SECMEM_UT_TEST)
	if (feature_id == DDR_SEC_SION) {
		g_cur_uuid = g_sec_uuid[ION_UUID_NUM];
		g_uuid_get_flag = UUID_GET;
		return OK;
	}
#endif

	if (feature_id == DDR_SEC_TUI || feature_id == DDR_SEC_EID ||
		feature_id == DDR_SEC_SION) {
		return OK; /* sec cfg by secos, not by ta */
	}

	if (SRE_TaskSelf(&task_id) != OK) {
		PRINT_ERROR("get sub_rgn task id error\n");
		return ERROR;
	}

	pid = (int)(task_id & LOW_MASK_16BIT);
	if (hm_getuuid(pid, &spawn_uuid) != OK) {
		PRINT_ERROR("get uuid error, pid:%d\n", pid);
		return ERROR;
	}

	g_cur_uuid = spawn_uuid.uuid;
	g_uuid_get_flag = UUID_GET;

	switch (feature_id) {
		case DDR_SEC_TINY:
			if (cmp_uuid(&g_cur_uuid, &g_sec_uuid[HIAI_TINY_UUID_NUM]) != OK &&
				cmp_uuid(&g_cur_uuid, &g_sec_uuid[ION_UUID_NUM]) != OK) {
				ret = ERROR;
			}
			break;
		case DDR_SEC_FACE:
			if (sec_face_check_uuid_fail()) {
				ret = ERROR;
			}
			break;
		default:
			PRINT_ERROR("wrong feature_id\n");
			return ERROR;
	}

	if (ret != OK) {
		PRINT_ERROR("verify error, %x-%hx-%hx-%llx", g_cur_uuid.timeLow, g_cur_uuid.timeMid,
			    g_cur_uuid.timeHiAndVersion, *(u64 *)(&(g_cur_uuid.clockSeqAndNode[0])));
	}

	return ret;
}

static int transform_sglist_to_sion(struct sglist *sglist,
					   enum SEC_FEATURE feature_id,
					   DDR_CFG_TYPE ddr_cfg_type,
					   int ta_state)
{
	if (g_uuid_get_flag == UUID_GET) {
		if (ddr_cfg_type == DDR_SET_SEC) {
			if (sion_record_sglist(sglist, &g_cur_uuid, feature_id) != OK) {
				PRINT_ERROR("sion_record_sglist fail\n");
				return ERROR;
			}
		} else if (ddr_cfg_type == DDR_UNSET_SEC && ta_state == TA_STATE_NORMAL) {
			if (sion_record_remove(sglist, &g_cur_uuid) != OK) {
				PRINT_ERROR("sion_record_remove fail\n");
				return ERROR;
			}
		}
	}

	return OK;
}
static int sub_rgn_feature_cfg(struct sglist *sglist, enum SEC_FEATURE feature_id, DDR_CFG_TYPE ddr_cfg_type)
{
	int ret;
	TEE_PAGEINFO *segment_info = NULL;
	int feature_num;
	u32 segment_num;
	u32 sub_rgn_cfg_addr, sub_rgn_cfg_size;

	if (check_uuid(feature_id) != OK) {
		PRINT_ERROR("check uuid fail\n");
		return ERROR;
	}

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_SUBBIT_RGN_CFG, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	/* get feature_num */
	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		if (feature_id == g_sub_rgn_cfg_table[feature_num].sec_feature) {
			break;
		}
	}

	if (feature_num >= SUB_RGN_FEATURE_MAX) {
		PRINT_ERROR("wrong feature_num: %u\n", feature_num);
		ret = ERROR;
		goto err_proc;
	}

	if (check_sglist(sglist, feature_num, ddr_cfg_type) != OK) {
		PRINT_ERROR("feature_num:%u, check_sglist fail\n", feature_num);
		ret = ERROR;
		goto err_proc;
	}

	/* cfg segment */
	for (segment_num = 0; segment_num < (sglist->infoLength); segment_num++) {
		segment_info = (TEE_PAGEINFO *)(sglist->info + segment_num);
		if (ddr_cfg_type == DDR_SET_SEC) {
			if (check_segment(segment_info) != OK) {
				PRINT_ERROR("feature_num:%u, segment_num:%u, check_segment fail\n", feature_num, segment_num);
				ret = ERROR;
				goto err_proc;
			}
		}

		if (segment_info->phys_addr >= g_sub_rgn_cfg_table[feature_num].start_addr) {
			sub_rgn_cfg_addr = segment_info->phys_addr - g_sub_rgn_cfg_table[feature_num].start_addr;
		} else {
			ret = ERROR;
			PRINT_ERROR("wrong seg_addr\n");
			PRINT_DEBUG("seg_addr:0x%llx, cma_start:0x%x\n", segment_info->phys_addr, g_sub_rgn_cfg_table[feature_num].start_addr);
			goto err_proc;
		}
		sub_rgn_cfg_size = segment_info->npages * PAGE_SIZE;
		PRINT_INFO("sub_rgn_cfg_addr:%x, sub_rgn_cfg_size:%x\n", sub_rgn_cfg_addr, sub_rgn_cfg_size);
		ret = sub_rgn_cfg(&(g_sub_rgn_cfg_table[feature_num]), sub_rgn_cfg_addr, sub_rgn_cfg_size, ddr_cfg_type);
		if (ret != OK) {
			PRINT_ERROR("sub_rgn_cfg fail\n");
			PRINT_DEBUG("seg_addr:0x%llx, seg_size:0x%x\n", segment_info->phys_addr, sub_rgn_cfg_size);
			goto err_proc;
		}
	}

err_proc:
#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_SUBBIT_RGN_CFG, DDR_AUTOFSGT_LOGIC_EN);
#endif

	return ret;
}

static int check_face_segment(TEE_PAGEINFO *segment_info, u32 *feature_num, DDR_CFG_TYPE ddr_cfg_type)
{
	u32 segment_feature_num;
	u64 segment_size;
	u64 segment_start_addr, segment_end_addr;

	segment_start_addr = segment_info->phys_addr;
	segment_size = (u64)segment_info->npages * PAGE_SIZE;
	segment_end_addr = segment_start_addr + segment_size;

	if (segment_start_addr >= SMEM_CMA_START && segment_end_addr <= SMEM_CMA_END) {
		segment_feature_num = FACE_3D_TA_FEATURE_NUM;
	} else if (segment_start_addr >= FACE_CMA_START && segment_end_addr <= FACE_CMA_END) {
		segment_feature_num = FACE_3D_FEATURE_NUM;
	} else if (segment_start_addr >= HISI_CMA_START && segment_end_addr <= HISI_CMA_END) {
		segment_feature_num = FACE_2D_FEATURE_NUM;
	} else {
		PRINT_ERROR("face error, not find feature num\n");
		PRINT_DEBUG("s_addr:0x%llx, size:0x%llx\n", segment_start_addr, segment_size);
		return ERROR;
	}

	if (ddr_cfg_type != DDR_CHECK_SEC) { /* add may not align */
		if (segment_size % g_sub_rgn_cfg_table[segment_feature_num].granularity_size != 0) {
			PRINT_ERROR("size is not align\n");
			PRINT_DEBUG("wrong segment_size:0x%x, npages %u, PAGE_SIZE 0x%x\n", segment_size, segment_info->npages, PAGE_SIZE);
			return ERROR;
		}
	}

	if (ddr_cfg_type == DDR_SET_SEC) {
		if (check_segment(segment_info) != OK) {
			PRINT_ERROR("segment_feature_num:%u, check_segment fail\n", segment_feature_num);
			return ERROR;
		}
	}

	*feature_num = segment_feature_num;
	return OK;
}

static int face_feature_cfg(struct sglist *sglist, enum SEC_FEATURE feature_id, DDR_CFG_TYPE ddr_cfg_type)
{
	int ret = ERROR;
	TEE_PAGEINFO *segment_info = NULL;
	u32 segment_feature_num = 0;
	u32 segment_num, segment_size, sub_rgn_cfg_addr;
	u64 segment_start_addr;

	if (check_uuid(feature_id) != OK) {
		PRINT_ERROR("check uuid fail\n");
		return ERROR;
	}

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_FACE_CFG, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	/* cfg segment */
	for (segment_num = 0; segment_num < (sglist->infoLength); segment_num++) {
		segment_info = (TEE_PAGEINFO *)(sglist->info + segment_num); /* add segment_num to get segment_num addr */
		segment_start_addr = segment_info->phys_addr;
		segment_size = segment_info->npages * PAGE_SIZE;

		if (check_face_segment(segment_info, &segment_feature_num, ddr_cfg_type) == ERROR) {
			PRINT_ERROR("check_face_segment error, segment_feature_num:%u, ddr_cfg_type:%u\n", segment_feature_num, ddr_cfg_type);
			ret = ERROR;
			goto err_proc;
		}

		sub_rgn_cfg_addr = segment_start_addr - g_sub_rgn_cfg_table[segment_feature_num].start_addr;
		PRINT_INFO("cfg_feature:%u, sub_rgn_cfg_addr:0x%x, segment_size:0x%x\n", segment_feature_num, sub_rgn_cfg_addr, segment_size);
		ret = sub_rgn_cfg(&(g_sub_rgn_cfg_table[segment_feature_num]), sub_rgn_cfg_addr, segment_size, ddr_cfg_type);
		if (ret != OK) {
			PRINT_ERROR("sub_rgn_cfg fail\n");
			PRINT_DEBUG("seg_addr:0x%llx, seg_size:0x%x\n", segment_info->phys_addr, segment_size);
			goto err_proc;
		}
	}

err_proc:
#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_FACE_CFG, DDR_AUTOFSGT_LOGIC_EN);
#endif

	return ret;
}

static int ddr_sec_cfg_internel(struct sglist *sglist, int feature_id, int ddr_cfg_type, int ta_state)
{
	int ret = OK;

	if (sglist == NULL) {
		PRINT_ERROR("sglist is null\n");
		return ERROR;
	}

	if (sglist->infoLength > SUB_BIT_MAX_NUM) {
		PRINT_ERROR("wrong infoLength:%u\n", sglist->infoLength);
		return ERROR;
	}

	if (sglist->infoLength == 0) {
		PRINT_ERROR("Warning:sglist infoLength is 0\n");
		return OK;
	}

	if (pthread_mutex_lock(&g_sec_pthread_lock) != OK) {
		PRINT_ERROR("check:Wait lock_flag failed!\n");
		return ERROR;
	}

	PRINT_INFO("[ddr_sec_cfg] feature_id:0x%x, ddr_cfg_type:%d\n", feature_id, ddr_cfg_type);
	g_uuid_get_flag = UUID_NOT_GET;

	switch (feature_id) {
		case DDR_SEC_TINY:
		case DDR_SEC_TUI:
		case DDR_SEC_EID:
			ret = sub_rgn_feature_cfg(sglist, feature_id, ddr_cfg_type);
			break;
		case DDR_SEC_FACE:
		case DDR_SEC_SION: /* for old plan */
			ret = face_feature_cfg(sglist, feature_id, ddr_cfg_type);
			break;
		case DDR_DRM_PRO:
			ret = tzmp2_pro_cfg(sglist, feature_id, ddr_cfg_type);
			break;
		default:
			PRINT_ERROR("wrong feature_id\n");
			ret = ERROR;
			break;
	}

	if (ret != OK) {
		PRINT_ERROR("feature_id:0x%x, ddr_cfg_type:%d, ddr_sec_cfg fail!\n", feature_id, ddr_cfg_type);
	} else {
		ret = transform_sglist_to_sion(sglist, feature_id, ddr_cfg_type, ta_state);
	}

	if (pthread_mutex_unlock(&g_sec_pthread_lock) != OK) {
		ret = ERROR;
		PRINT_ERROR("cfg:Release lock_flag failed!\n");
	}

	return ret;
}

#ifdef CONFIG_SOC_WE_WORKAROUND
int __ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type)
{
	return ddr_sec_cfg_internel(sglist, feature_id, ddr_cfg_type, TA_STATE_NORMAL);
}
#else
int ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type)
{
	return ddr_sec_cfg_internel(sglist, feature_id, ddr_cfg_type, TA_STATE_NORMAL);
}
#endif

int ddr_unset_sec_for_ta_crash(struct sglist *sglist, int feature_id)
{
	return ddr_sec_cfg_internel(sglist, feature_id, DDR_UNSET_SEC, TA_STATE_CRASHED);
}

int check_sglist_pid(struct sglist *sglist, int feature_id)
{
	if (sglist == NULL) {
		PRINT_ERROR("sglist is null\n");
		return ERROR;
	}

	return ddr_sec_cfg(sglist, feature_id, DDR_CHECK_SEC);
}

int check_unsec_sglist(struct sglist *sglist)
{
	int ret = OK;
	u32 segment_num;
	TEE_PAGEINFO *segment_info = NULL;
	u64 segment_start_addr, segment_end_addr;

	if (sglist == NULL) {
		PRINT_ERROR("sglist is null\n");
		return ERROR;
	}

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CHECK_UNSEC_SGLIST, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	for (segment_num = 0; segment_num < (sglist->infoLength); segment_num++) {
		segment_info = (TEE_PAGEINFO *)(sglist->info + segment_num);
		segment_start_addr = segment_info->phys_addr;
		segment_end_addr = segment_start_addr + (u64)segment_info->npages * PAGE_SIZE;
		ret = is_not_covered_by_normal_region(segment_start_addr, segment_end_addr);
		if (ret != OK) {
			PRINT_ERROR("check_unsec_sglist fail\n");
			PRINT_DEBUG("sglist have sec addr, s_s_addr:0x%llx, s_e_addr:0x%llx\n", segment_start_addr, segment_end_addr);
			goto err_proc;
		}
	}

err_proc:
#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CHECK_UNSEC_SGLIST, DDR_AUTOFSGT_LOGIC_EN);
#endif

	return ret;
}

static int check_cma_addr(u64 start_addr, u64 end_addr)
{
	if (start_addr > end_addr) {
		PRINT_ERROR("cma_start beyond cma_end\n");
		return ERROR;
	}

	if ((start_addr != HISI_CMA_START) && (start_addr != FACE_CMA_START) &&
		(start_addr != TINY_CMA_START) && (start_addr != SMEM_CMA_START)) {
		PRINT_ERROR("wrong start_addr\n");
		return ERROR;
	}

	/* region cfg end_addr may beyond cma end_addr for aligning */
	if ((end_addr < HISI_CMA_END) && (end_addr < FACE_CMA_END) &&
		(end_addr < TINY_CMA_END) && (end_addr < SMEM_CMA_END)) {
		PRINT_ERROR("wrong end_addr\n");
		return ERROR;
	}

	return OK;
}

static int sub_region_init(void)
{
	u32 feature_num;
	u32 cma_granularity_size;
	u64 cma_start_addr, cma_end_addr;
	SOC_DMSS_ASI_SEC_RGN_MAP0_UNION rgn_map0;
	SOC_DMSS_ASI_SEC_RGN_MAP1_UNION rgn_map1;

	for (feature_num = 0; feature_num < SUB_RGN_FEATURE_MAX; feature_num++) {
		rgn_map0.value = readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(SOC_ACPU_DMSS_BASE_ADDR, g_sub_rgn_cfg_table[feature_num].region_num, CPU_ASI_NUM));
		rgn_map1.value = readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(SOC_ACPU_DMSS_BASE_ADDR, g_sub_rgn_cfg_table[feature_num].region_num, CPU_ASI_NUM));
		cma_start_addr = (u64)(rgn_map0.reg.rgn_base_addr) << DDR_SEC_GRANULARITY;
		cma_end_addr = (((u64)(rgn_map1.reg.rgn_top_addr) << DDR_SEC_GRANULARITY) | SEC_RGN_ADDR_MASK) + 0x1;

		if (check_cma_addr(cma_start_addr, cma_end_addr) != OK) {
			PRINT_DEBUG("check_cma_addr fail, start:0x%llx, end:0x%llx\n", cma_start_addr, cma_end_addr);
			return ERROR;
		}
		if (rgn_map0.reg.sub_rgn_zone == 0x0) {
			cma_granularity_size = SUB_GRN_ZONE_1M;
		} else if ((rgn_map0.reg.sub_rgn_zone) == 0x1) {
			cma_granularity_size = SUB_GRN_ZONE_2M;
		} else {
			PRINT_ERROR("wrong sub_rgn_zone: %u\n", rgn_map0.reg.sub_rgn_zone);
			return ERROR;
		}
		PRINT_INFO("feature_num: %u, cma_start_addr: 0x%llx, cma_end_addr: 0x%llx, cma_granularity_size: 0x%x!\n",
					feature_num, cma_start_addr, cma_end_addr, cma_granularity_size);
		g_sub_rgn_cfg_table[feature_num].start_addr = cma_start_addr;
		g_sub_rgn_cfg_table[feature_num].end_addr = cma_end_addr;
		g_sub_rgn_cfg_table[feature_num].granularity_size = cma_granularity_size;
	}

	return OK;
}

/* old interface, discarding */
int mddrc_sec_clean(u64 start_addr, u64 end_addr)
{
	(void)start_addr;
	(void)end_addr;

	return ERROR;
}

int mddrc_sec_cfg(u64 start_addr, u64 end_addr)
{
	(void)start_addr;
	(void)end_addr;

	return ERROR;
}

/* addr should be phy_addr  */
unsigned int is_sec_addr(u64 start_addr, u64 end_addr)
{
	if (is_not_covered_by_normal_region(start_addr, end_addr) == ERROR) {
		return SEC_ADDR;
	} else {
		return UNSEC_ADDR;
	}
}

/* ddr sec init */
int sec_region_init(void)
{
	unsigned int i;
	int ret = OK;

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_SEC_RGN_INIT, DDR_AUTOFSGT_LOGIC_DIS);
#endif
	for (i = 0; i < ASI_NUM_MAX; i++) {
		g_rgn_num[i] = get_rgn_num_max(i);
	}

	ret = sub_region_init();

#ifdef CONFIG_HISI_SEC_DDR_TEST
	PRINT_ERROR("sec_region_test begin\n");
	PRINT_ERROR("sec_region_test %d.\n", sec_region_test());
#endif

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_SEC_RGN_INIT, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return ret;
}
