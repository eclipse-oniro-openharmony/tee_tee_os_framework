/*************************************************************
*文  件  名  字:	sec_region.c
*
*文  件  描  述:	sec_region.c
*
*作  者  名  字:	 x00431728
*
*生  成  时  间:	2018-07-11
*************************************************************/


/**********************************************************
 头文件
**********************************************************/
#include <stdint.h>
#include <pthread.h>
#include <register_ops.h> // readl
#include "mem_page_ops.h"
#include "tee_log.h"
#include "securec.h"
#include "sec_region.h"
#include <sec_region_ops.h>

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
#include <hisi_ddr_autofsgt_proxy_secure_os.h>
#endif

/**********************************************************
 全局变量
**********************************************************/
static unsigned int g_rgn_num[ASI_NUM_MAX];
static SEC_RGN_CFG g_sion_sec_rgn[SEC_RGN_SION_RESERVED_NUM];
#ifdef CONFIG_HISI_DDR_SEC_IDENTIFICATION
static SEC_RGN_CFG g_identification_sec_rgn = {0};
#endif
#ifdef CONFIG_HISI_DDR_SEC_HIFI_RESET
static SEC_RGN_CFG g_hifi_reset_sec_rgn = {0};
#endif
#ifdef CONFIG_HISI_DDR_SEC_TUI
static SEC_RGN_CFG g_tui_sec_rgn[SEC_RGN_TUI_RESERVED_NUM];
#endif
pthread_mutex_t g_sec_pthread_lock = PTHREAD_MUTEX_INITIALIZER;
/**********************************************************
 宏
**********************************************************/

/*check the sec number and region number*/
#define MDDRC_SEC_CHECK_SECANDRGN(ret, asi_num, rgn_num)\
do {\
	if (asi_num >= ASI_NUM_MAX) {\
		PRINT_ERROR("[%s]_%d: sec num %d is invalid\n", __func__, __LINE__, asi_num);\
		ret = ERROR;\
	}\
	else {\
		if (rgn_num >= g_rgn_num[asi_num]) {\
			PRINT_ERROR("[%s]_%d: region %d not in scope :[0-%d]\n",\
			__func__, __LINE__, rgn_num, g_rgn_num[asi_num]-1);\
			ret = ERROR;\
		}\
	}\
} while (0)

#define CHECK_RET(ret)\
do {\
	if (OK != ret) {\
		goto err_proc;\
	}\
} while (0)

#define SEC_SION_RGN_USE_NOW(rgn)	(SEC_RGN_SION_RESERVED - (rgn))
/**********************************************************
 函数
**********************************************************/
static unsigned int get_rgn_num_max(unsigned int asi_num)
{
	SOC_DMSS_ASI_RTL_INF2_UNION asi_rtl_inf2;
	asi_rtl_inf2.value = readl((u32)SOC_DMSS_ASI_RTL_INF2_ADDR(REG_BASE_DMSS, asi_num));
	return (asi_rtl_inf2.reg.rtl_sec_rgn_num);
}
/*****************************************************
	检查rgn 是否可用
	asi_num 和rgn_num 不可以操作最大值
	该rgn 不可以已经被使用
*******************************************/
static int check_rgn_usable(unsigned int asi_num, unsigned int rgn_num)
{
	int ret = OK;
	unsigned int value;

	MDDRC_SEC_CHECK_SECANDRGN(ret, asi_num, rgn_num);

	value = readl(SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
	if ((value >> SOC_DMSS_ASI_SEC_RGN_MAP0_rgn_en_START) & 0x1) {
		PRINT_DEBUG("map0:0x%x, map1:0x%x, wr:0x%x, rd:0x%x\n", \
					readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(REG_BASE_DMSS, rgn_num, asi_num)), \
					readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(REG_BASE_DMSS, rgn_num, asi_num)), \
					readl((u32)SOC_DMSS_ASI_SEC_MID_WR_ADDR(REG_BASE_DMSS, rgn_num, asi_num)), \
					readl((u32)SOC_DMSS_ASI_SEC_MID_RD_ADDR(REG_BASE_DMSS, rgn_num, asi_num)));
		ret = ERROR;
	}

	return ret;
}

/*one region*/
static int sec_region_cfg(unsigned int asi_num, unsigned int rgn_num, const SEC_RGN_CFG* sec_rgn_cfg)
{
	int ret = OK;
	volatile SOC_DMSS_ASI_SEC_RGN_MAP0_UNION *sec_rgn_map0 = NULL;
	volatile SOC_DMSS_ASI_SEC_RGN_MAP1_UNION *sec_rgn_map1 = NULL;
	volatile SOC_DMSS_ASI_SEC_MID_WR_UNION *sec_mid_wr = NULL;
	volatile SOC_DMSS_ASI_SEC_MID_RD_UNION *sec_mid_rd = NULL;

	ret = check_rgn_usable(asi_num, rgn_num);

	if (OK != ret || NULL == sec_rgn_cfg) {
		PRINT_ERROR("[%s]_%d: asi%x rgn%x cfg err!\n", __func__, __LINE__, asi_num, rgn_num);
		return ERROR;
	}

	if ((sec_rgn_cfg->start_addr & SEC_RGN_ADDR_MASK) || (sec_rgn_cfg->end_addr & SEC_RGN_ADDR_MASK)) {
		PRINT_ERROR("[%s]_%d: cfg err!\n", __func__, __LINE__);
		PRINT_DEBUG("[%s]_%d: asi%x rgn%x addr err! start:0x%llx,end0x%llx;\n", __func__, __LINE__, asi_num, rgn_num,
			sec_rgn_cfg->start_addr, sec_rgn_cfg->end_addr);
		return ERROR;
	}

	sec_rgn_map0 = (volatile SOC_DMSS_ASI_SEC_RGN_MAP0_UNION *)
		((unsigned long)SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
	sec_rgn_map1 = (volatile SOC_DMSS_ASI_SEC_RGN_MAP1_UNION *)
		((unsigned long)SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
	sec_mid_wr = (volatile SOC_DMSS_ASI_SEC_MID_WR_UNION *)
		((unsigned long)SOC_DMSS_ASI_SEC_MID_WR_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
	sec_mid_rd = (volatile SOC_DMSS_ASI_SEC_MID_RD_UNION *)
		((unsigned long)SOC_DMSS_ASI_SEC_MID_RD_ADDR(REG_BASE_DMSS, rgn_num, asi_num));

	sec_rgn_map0->reg.rgn_en = 0;

	sec_rgn_map0->reg.rgn_base_addr = ((~(SEC_RGN_ADDR_MASK)) & sec_rgn_cfg->start_addr) >> SEC_RGN_ADDR_SHIFT;
	sec_rgn_map1->reg.rgn_top_addr = ((~(SEC_RGN_ADDR_MASK)) & (sec_rgn_cfg->end_addr - 1)) >> SEC_RGN_ADDR_SHIFT;
	sec_rgn_map1->reg.sp = sec_rgn_cfg->attri;
	sec_mid_wr->value = sec_rgn_cfg->mid_wr;
	sec_mid_rd->value = sec_rgn_cfg->mid_rd;
	sec_rgn_map0->reg.rgn_en = sec_rgn_cfg->rgn_en;

	return OK;
}

/*
	清空region
	asi_num 和 rgn_num的合法性在外层判断
*/
static inline void sec_region_clean(unsigned int asi_num, unsigned int rgn_num)
{
	unsigned int value;

	value = readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
	writel((~(1UL << SOC_DMSS_ASI_SEC_RGN_MAP0_rgn_en_START)) & value,
		SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(REG_BASE_DMSS, rgn_num, asi_num));

	writel(ALL_MID, SOC_DMSS_ASI_SEC_MID_WR_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
	writel(ALL_MID, SOC_DMSS_ASI_SEC_MID_RD_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
	writel(0, SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
	writel(0, SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
}

static int sec_region_cfg_mask(unsigned int asi_mask, unsigned int reserved_reg, const SEC_RGN_CFG* sec_rgn_cfg)
{
	unsigned int set_asi, clean_asi;
	int ret = OK;

	if (NULL == sec_rgn_cfg) {
		PRINT_ERROR("[%s]_%d: sec_rgn_cfg is NULL!\n", __func__, __LINE__);
		return ERROR;
	}

	for (set_asi = 0; set_asi < ASI_NUM_MAX; set_asi++) {
		if ((1 << set_asi) & asi_mask) {
			ret = sec_region_cfg(set_asi, g_rgn_num[set_asi] - reserved_reg, sec_rgn_cfg);
			if (ret) {
				PRINT_ERROR("sec_region_cfg fail\n");
				break;
			}
		}
	}

	/* if set sec region error */
	for (clean_asi = 0; (OK != ret) && (clean_asi < set_asi); clean_asi++) {
		if ((1 << clean_asi) & asi_mask) {
			sec_region_clean(clean_asi, g_rgn_num[clean_asi] - reserved_reg);
		}
	}

	return ret;
}

static int is_not_covered_by_region(u64 start_addr, u64 end_addr)
{
	unsigned int asi_num, rgn_num;
	SOC_DMSS_ASI_SEC_RGN_MAP0_UNION rgn_map0;
	SOC_DMSS_ASI_SEC_RGN_MAP1_UNION rgn_map1;
	unsigned long long rgn_start, rgn_end;

	if (start_addr >= end_addr)
		return ERROR;

	for (asi_num = 0; asi_num < ASI_NUM_MAX; asi_num++)
	{
		if (0 == (BIT(asi_num) & DDR_SEC_ALL_ASI_MASK))
			continue;
		for (rgn_num = 1; rgn_num < g_rgn_num[asi_num]; rgn_num++)
		{
			rgn_map0.value = readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
			if (0 == rgn_map0.reg.rgn_en)
				continue;
			rgn_map1.value = readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
			rgn_start = (u64)(rgn_map0.reg.rgn_base_addr) << SEC_RGN_ADDR_SHIFT;
			rgn_end = (((u64)(rgn_map1.reg.rgn_top_addr) << SEC_RGN_ADDR_SHIFT) | SEC_RGN_ADDR_MASK) + 0x1;
			/*rgn_start~rgn_end 前闭后开*/
			if ((start_addr >= rgn_start && start_addr < rgn_end)
				|| (end_addr > rgn_start && end_addr <= rgn_end)
				|| (rgn_start < rgn_end && start_addr <= rgn_start && end_addr >= rgn_end))
			{
				PRINT_ERROR("is covered by region\n");
				PRINT_DEBUG("a_n%d, r_n%d, 0x%x, 0x%x\n", asi_num, rgn_num, rgn_map0.value, rgn_map1.value);
				return ERROR;	/*is covered by region*/
			}
		}
	}

	return OK;	/*is not covered by region*/
}

/******************************************************/
/*ddr sec interface for sion*/
/******************************************************/
static unsigned int find_region_by_addr_for_sion(u64 start_addr, u64 end_addr)
{
	unsigned int i;
	for (i = 0; i < SEC_RGN_SION_RESERVED_NUM; i++) {
		if ((start_addr == g_sion_sec_rgn[i].start_addr) && (end_addr == g_sion_sec_rgn[i].end_addr)) {
			return i;
		}
	}

	return INVALID_REGION_INDEX;
}

static unsigned int sec_get_unused_region_for_sion()
{
	unsigned int i;
	for (i = 0; i < SEC_RGN_SION_RESERVED_NUM; i++) {
		if (0 == g_sion_sec_rgn[i].rgn_en) {
			return i;
		}
	}
	return INVALID_REGION_INDEX;
}

static int ddr_sec_cfg_for_sion(u64 start_addr, u64 end_addr)
{
	PRINT_INFO("++ddr_sec_cfg_for_sion++ start 0x%llx, end 0x%llx\n", start_addr, end_addr);

	unsigned int rgn_index;
	int ret = ERROR;
	SEC_RGN_CFG cfg_data = {0};

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	if (ERROR == is_not_covered_by_region(start_addr, end_addr)){
		PRINT_ERROR("cfg_s, addr has been covered!\n");
		goto err_proc;
	}

	rgn_index = sec_get_unused_region_for_sion();
	if (rgn_index >= SEC_RGN_SION_RESERVED_NUM) {
		PRINT_ERROR("get_unused_region fail\n");
		goto err_proc;
	}

	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;
	/*port 0 modem 8/9 GPU forbid*/
	cfg_data.mid_rd = FORBID_MID;
	cfg_data.mid_wr = FORBID_MID;
	cfg_data.attri = RW_FORBID;

	ret = sec_region_cfg_mask(MODEM_CCPU_ASI_MASK | GPU_ASI_MASK, (SEC_SION_RGN_USE_NOW(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port 2 ivp SR/SW, vdec venc forbid*/
	cfg_data.mid_rd = IVP_ALL;
	cfg_data.mid_wr = IVP_ALL;
	cfg_data.attri = SEC_WR|SEC_RD;

	ret = sec_region_cfg_mask(VDEC_IVP_ASI_MASK, (SEC_SION_RGN_USE_NOW(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port 3/4 isp ipp_orb(cpe) SW\SR, dss ipp_other forbid*/
	cfg_data.mid_rd = (ISP_ALL | (1 << IPP_SUBSYS_ORB_MID));
	cfg_data.mid_wr = (ISP_ALL | (1 << IPP_SUBSYS_ORB_MID));
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(ISP_DSS_ASI_MASK, (SEC_SION_RGN_USE_NOW(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port 7 subsys cc712 SW\SR*/
	cfg_data.mid_rd = (1 << CC712_MID);
	cfg_data.mid_wr = (1 << CC712_MID);
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(SUBSYS_ASI_MASK, (SEC_SION_RGN_USE_NOW(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port 5/6 CPU SW\SR*/
	cfg_data.mid_rd = CPU_ALL;
	cfg_data.mid_wr = CPU_ALL;
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(CPU_ASI_MASK, (SEC_SION_RGN_USE_NOW(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port 8/9 NPU SW\SR*/
	cfg_data.mid_rd = NPU_ALL;
	cfg_data.mid_wr = NPU_ALL;
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(NPU_ASI_MASK, (SEC_SION_RGN_USE_NOW(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	g_sion_sec_rgn[rgn_index].rgn_en = 1;
	g_sion_sec_rgn[rgn_index].start_addr = start_addr;
	g_sion_sec_rgn[rgn_index].end_addr = end_addr;

err_proc:

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return ret;
}

static int ddr_sec_clean_for_sion(u64 start_addr, u64 end_addr)
{
	unsigned int rgn_index;
	unsigned int i;
	PRINT_INFO("++ddr_sec_clean_for_sion++ start 0x%llx, end 0x%llx\n", start_addr, end_addr);
	rgn_index = find_region_by_addr_for_sion(start_addr, end_addr);

	if (rgn_index >= SEC_RGN_SION_RESERVED_NUM) {
		PRINT_ERROR("find_region_by_addr_for_sion fail\n");
		return ERROR;
	}

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif


	/*clean sec region*/
	for (i = 0; i < ASI_NUM_MAX; i++) {
		sec_region_clean(i, g_rgn_num[i] - SEC_SION_RGN_USE_NOW(rgn_index));
	}

	g_sion_sec_rgn[rgn_index].rgn_en = 0;
	g_sion_sec_rgn[rgn_index].start_addr = 0;
	g_sion_sec_rgn[rgn_index].end_addr = 0;


#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return OK;
}

static unsigned int ddr_sec_check_for_sion(u64 start_addr, u64 end_addr)
{
	u32 i, loop_flag;

	if(start_addr >= end_addr){
		PRINT_ERROR("start_addr is beyond end_addr!\n");
		return UNSEC_ADDR;
	}

	do{
		loop_flag = 0;
		for (i = 0; i < SEC_RGN_SION_RESERVED_NUM; i++) {
			if ((start_addr >= g_sion_sec_rgn[i].start_addr) && (start_addr < g_sion_sec_rgn[i].end_addr)) {
				if(end_addr > g_sion_sec_rgn[i].end_addr){
					start_addr = g_sion_sec_rgn[i].end_addr;
					loop_flag = 1;
					break;
				}
				return SEC_ADDR;/*secure*/
			}
		}
	}while (loop_flag);

	return UNSEC_ADDR;
}

/******************************************************/
/*ddr sec interface for identification*/
/******************************************************/
#ifdef CONFIG_HISI_DDR_SEC_IDENTIFICATION
static int ddr_sec_cfg_for_identification(u64 start_addr, u64 end_addr)
{
	int ret = ERROR;
	SEC_RGN_CFG cfg_data = {0};

	if (g_identification_sec_rgn.rgn_en)
	{
		PRINT_ERROR("identification region has been set!\n");
		return ERROR;
	}

	PRINT_INFO("ddr_sec_cfg_for_identification:start 0x%llx, end 0x%llx\n", start_addr, end_addr);

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	if (ERROR == is_not_covered_by_region(start_addr, end_addr))
	{
		PRINT_ERROR("identification addr has been covered!\n");
		return ERROR;
	}
	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;

	/*port modem vdec_ivp isp_dss npu gpu forbid*/
	cfg_data.mid_rd = FORBID_MID;
	cfg_data.mid_wr = FORBID_MID;
	cfg_data.attri = RW_FORBID;
	ret = sec_region_cfg_mask(MODEM_CCPU_ASI_MASK | VDEC_IVP_ASI_MASK | ISP_DSS_ASI_MASK | NPU_ASI_MASK | GPU_ASI_MASK, SEC_RGN_IDENTIFICATION_RESERVED, &cfg_data);
	CHECK_RET(ret);

	/*port CPU SW\SR*/
	cfg_data.mid_rd = CPU_ALL;
	cfg_data.mid_wr = CPU_ALL;
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(CPU_ASI_MASK, SEC_RGN_IDENTIFICATION_RESERVED, &cfg_data);
	CHECK_RET(ret);

	/*port subsys SW\SR*/
	cfg_data.mid_rd = (1 << DJTAG_M_MID) | (1 << CC712_MID) | (1 << DMAC_MID);
	cfg_data.mid_wr = (1 << DJTAG_M_MID) | (1 << CC712_MID) | (1 << DMAC_MID);
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(SUBSYS_ASI_MASK, SEC_RGN_IDENTIFICATION_RESERVED, &cfg_data);
	CHECK_RET(ret);

	g_identification_sec_rgn.rgn_en = 1;
	g_identification_sec_rgn.start_addr = start_addr;
	g_identification_sec_rgn.end_addr = end_addr;

err_proc:

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return ret;
}

static int ddr_sec_clean_for_identification(u64 start_addr, u64 end_addr)
{
	unsigned int i;

	if (0 == g_identification_sec_rgn.rgn_en)
	{
		PRINT_ERROR("identification region has not been set!\n");
		return ERROR;
	}

	PRINT_INFO("ddr_sec_clean_for_identification:start 0x%llx, end 0x%llx\n", start_addr, end_addr);

	if (start_addr != g_identification_sec_rgn.start_addr || end_addr != g_identification_sec_rgn.end_addr)
	{
		PRINT_ERROR("identification addr error!\n");
		return ERROR;
	}

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	/*clean sec region*/
	for (i = 0; i < ASI_NUM_MAX; i++) {
		sec_region_clean(i, g_rgn_num[i] - SEC_RGN_IDENTIFICATION_RESERVED);
	}

	g_identification_sec_rgn.rgn_en = 0;
	g_identification_sec_rgn.start_addr = 0;
	g_identification_sec_rgn.end_addr = 0;


#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return OK;
}
#endif

/******************************************************/
#ifdef CONFIG_HISI_DDR_SEC_HIFI_RESET
static int ddr_sec_cfg_for_hifi_reset(u64 start_addr, u64 end_addr)
{
	int ret = ERROR;
	SEC_RGN_CFG cfg_data = {0};

	if (g_hifi_reset_sec_rgn.rgn_en)
	{
		PRINT_ERROR("hifi reset region has been set!\n");
		return ERROR;
	}

	PRINT_INFO("ddr_sec_cfg_for_hifi_reset:start 0x%llx, end 0x%llx\n", start_addr, end_addr);

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	if (ERROR == is_not_covered_by_region(start_addr, end_addr))
	{
		PRINT_ERROR("hifi reset addr has been covered!\n");
		return ERROR;
	}

	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;

	/*port modem vdec_ivp isp_dss npu gpu forbid*/
	cfg_data.mid_rd = FORBID_MID;
	cfg_data.mid_wr = FORBID_MID;
	cfg_data.attri = RW_FORBID;
	ret = sec_region_cfg_mask(MODEM_CCPU_ASI_MASK | VDEC_IVP_ASI_MASK | ISP_DSS_ASI_MASK | NPU_ASI_MASK | GPU_ASI_MASK, SEC_RGN_HIFI_REBOOT_RESERVED, &cfg_data);
	CHECK_RET(ret);

	/*port CPU SW\SR*/
	cfg_data.mid_rd = CPU_ALL;
	cfg_data.mid_wr = CPU_ALL;
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(CPU_ASI_MASK, SEC_RGN_HIFI_REBOOT_RESERVED, &cfg_data);
	CHECK_RET(ret);

	/*port subsys SW\SR*/
	cfg_data.mid_rd = (1 << CC712_MID);
	cfg_data.mid_wr = (1 << CC712_MID);
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(SUBSYS_ASI_MASK, SEC_RGN_HIFI_REBOOT_RESERVED, &cfg_data);
	CHECK_RET(ret);

	g_hifi_reset_sec_rgn.rgn_en = 1;
	g_hifi_reset_sec_rgn.start_addr = start_addr;
	g_hifi_reset_sec_rgn.end_addr = end_addr;

err_proc:

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return ret;
}

static int ddr_sec_clean_for_hifi_reset(u64 start_addr, u64 end_addr)
{
	unsigned int i;

	if (0 == g_hifi_reset_sec_rgn.rgn_en)
	{
		PRINT_ERROR("hifi reset region has not been set!\n");
		return ERROR;
	}

	PRINT_INFO("ddr_sec_clean_for_hifi_reset:start 0x%llx, end 0x%llx\n", start_addr, end_addr);

	if (start_addr != g_hifi_reset_sec_rgn.start_addr || end_addr != g_hifi_reset_sec_rgn.end_addr)
	{
		PRINT_ERROR("hifi reset addr error!\n");
		return ERROR;
	}

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	/*clean sec region*/
	for (i = 0; i < ASI_NUM_MAX; i++) {
		sec_region_clean(i, g_rgn_num[i] - SEC_RGN_HIFI_REBOOT_RESERVED);
	}

	g_hifi_reset_sec_rgn.rgn_en = 0;
	g_hifi_reset_sec_rgn.start_addr = 0;
	g_hifi_reset_sec_rgn.end_addr = 0;


#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return OK;
}
#endif

/******************************************************/
#ifdef CONFIG_HISI_DDR_SEC_CFC
int kernel_read_only_enable(u64 start_addr, u64 end_addr)
{
	unsigned int rgn_index;
	u64 allow_addr = 0;
	int ret = OK;
	SEC_RGN_CFG cfg_data;
	volatile SOC_DMSS_ASI_SEC_RGN_MAP1_UNION *sec_rgn_map1 = NULL;

	(void)memset_s(&cfg_data, sizeof(SEC_RGN_CFG), 0, sizeof(SEC_RGN_CFG));
	PRINT_DEBUG("kernel_read_only_enable start 0x%llx, end 0x%llx\n", start_addr, end_addr);

	if (start_addr >= end_addr) {
		PRINT_ERROR("start_addr >= end_addr\nn");
		return ERROR;
	}

	if ((start_addr & SEC_RGN_ADDR_MASK) || (end_addr & SEC_RGN_ADDR_MASK)) {
		PRINT_ERROR("addr low 16bit not 0\n");
		return ERROR;
	}

	/*port 5/6 CPU SW\SR*/
	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;
	cfg_data.mid_rd = CPU_ALL;
	cfg_data.mid_wr = CPU_ALL;
	cfg_data.attri = UNSEC_RD;

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	/* if kernel protect open*/
	rgn_index = g_rgn_num[CPU_ASI_NUM] - SEC_RGN_KERNEL_PROTECT_RESERVED;
	if (check_rgn_usable(CPU_ASI_NUM, rgn_index)) {
		sec_rgn_map1 = (volatile SOC_DMSS_ASI_SEC_RGN_MAP1_UNION *)
		((unsigned long)SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(REG_BASE_DMSS, rgn_index, CPU_ASI_NUM));

		allow_addr = (u64)(sec_rgn_map1->reg.rgn_top_addr + 1) << SEC_RGN_ADDR_SHIFT;

		if (start_addr < allow_addr) {
			sec_rgn_map1->reg.rgn_top_addr = (start_addr - 1) >> SEC_RGN_ADDR_SHIFT;
			cfg_data.end_addr = allow_addr;
		} else {
			PRINT_ERROR("start_addr is not allow\n");
			ret = ERROR;
		}
	} else if (end_addr > KERNEL_END_ADDR) {
		/*else if end_addr out of allow addr*/
		ret = ERROR_ADDR;
	}

	CHECK_RET(ret);

	PRINT_DEBUG("allow addr 0x%llx\n", allow_addr);

	ret = sec_region_cfg_mask(CPU_ASI_MASK, SEC_RGN_KERNEL_READ_ONLY_RESERVED, &cfg_data);
err_proc:
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return ret;
}
#endif

/******************************************************/
/*ddr sec interface for tui*/
/******************************************************/
#ifdef CONFIG_HISI_DDR_SEC_TUI
#define SEC_TUI_RGN_USE_NOW(rgn)	(SEC_RGN_TUI_RESERVED - (rgn))
static unsigned int sec_get_unused_region_for_tui()
{
	unsigned int i;
	for (i = 0; i < SEC_RGN_TUI_RESERVED_NUM; i++) {
		if (0 == g_tui_sec_rgn[i].rgn_en) {
			return i;
		}
	}
	return INVALID_REGION_INDEX;
}

static unsigned int find_region_by_addr_for_tui(u64 start_addr, u64 end_addr)
{
	unsigned int i;
	for (i = 0; i < SEC_RGN_TUI_RESERVED_NUM; i++) {
		if ((start_addr == g_tui_sec_rgn[i].start_addr) && (end_addr == g_tui_sec_rgn[i].end_addr)) {
			return i;
		}
	}

	return INVALID_REGION_INDEX;
}

static int ddr_sec_cfg_for_tui(u64 start_addr, u64 end_addr)
{
	PRINT_INFO("++ddr_sec_cfg_for_tui++ start 0x%llx, end 0x%llx\n", start_addr, end_addr);

	unsigned int rgn_index;
	int ret = ERROR;
	SEC_RGN_CFG cfg_data = {0};

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif
	if (ERROR == is_not_covered_by_region(start_addr, end_addr)){
		PRINT_ERROR("%s, addr has been covered!\n", __func__);
		goto err_proc;
	}

	rgn_index = sec_get_unused_region_for_tui();
	if (rgn_index >= SEC_RGN_TUI_RESERVED_NUM) {
		PRINT_ERROR("get_unused_region fail\n");
		goto err_proc;
	}

	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;

	/*port modem vdec_ivp npu gpu forbid*/
	cfg_data.mid_rd = FORBID_MID;
	cfg_data.mid_wr = FORBID_MID;
	cfg_data.attri = RW_FORBID;
	ret = sec_region_cfg_mask(MODEM_CCPU_ASI_MASK | VDEC_IVP_ASI_MASK | NPU_ASI_MASK | GPU_ASI_MASK, (SEC_TUI_RGN_USE_NOW(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port isp_dss SW\SR*/
	cfg_data.mid_rd = DSS_ALL;
	cfg_data.mid_wr = DSS_ALL;
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(ISP_DSS_ASI_MASK, (SEC_TUI_RGN_USE_NOW(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port CPU SW\SR*/
	cfg_data.mid_rd = CPU_ALL;
	cfg_data.mid_wr = CPU_ALL;
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(CPU_ASI_MASK, (SEC_TUI_RGN_USE_NOW(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port system cc712 SW\SR*/
	cfg_data.mid_rd = (1 << CC712_MID);
	cfg_data.mid_wr = (1 << CC712_MID);
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(SUBSYS_ASI_MASK, (SEC_TUI_RGN_USE_NOW(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	g_tui_sec_rgn[rgn_index].rgn_en = 1;
	g_tui_sec_rgn[rgn_index].start_addr = start_addr;
	g_tui_sec_rgn[rgn_index].end_addr = end_addr;

err_proc:

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return ret;
}

static int ddr_sec_clean_for_tui(u64 start_addr, u64 end_addr)
{
	unsigned int rgn_index;
	unsigned int i;
	PRINT_INFO("++ddr_sec_clean_for_tui++ start 0x%llx, end 0x%llx\n", start_addr, end_addr);
	rgn_index = find_region_by_addr_for_tui(start_addr, end_addr);

	if (rgn_index >= SEC_RGN_TUI_RESERVED_NUM) {
		PRINT_ERROR("find_region_by_addr_for_tui fail\n");
		return ERROR;
	}

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif


	/*clean sec region*/
	for (i = 0; i < ASI_NUM_MAX; i++) {
		sec_region_clean(i, g_rgn_num[i] - SEC_TUI_RGN_USE_NOW(rgn_index));
	}

	g_tui_sec_rgn[rgn_index].rgn_en = 0;
	g_tui_sec_rgn[rgn_index].start_addr = 0;
	g_tui_sec_rgn[rgn_index].end_addr = 0;


#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return OK;
}

static unsigned int ddr_sec_check_for_tui(u64 start_addr, u64 end_addr)
{
	u32 i, loop_flag;

	if(start_addr >= end_addr){
		PRINT_ERROR("start_addr is beyond end_addr!\n");
		return UNSEC_ADDR;
	}

	do{
		loop_flag = 0;
		for (i = 0; i < SEC_RGN_TUI_RESERVED_NUM; i++) {
			if ((start_addr >= g_tui_sec_rgn[i].start_addr) && (start_addr < g_tui_sec_rgn[i].end_addr)) {
				if(end_addr > g_tui_sec_rgn[i].end_addr){
					start_addr = g_tui_sec_rgn[i].end_addr;
					loop_flag = 1;
					break;
				}
				return SEC_ADDR;/*secure*/
			}
		}
	}while (loop_flag);

	return UNSEC_ADDR;
}
#endif
/******************************************************/
/*old interface, discarding*/
int mddrc_sec_clean(u64 start_addr, u64 end_addr)
{
	return ddr_sec_clean_for_feature(start_addr, end_addr, DDR_SEC_SION);
}

int mddrc_sec_cfg(u64 start_addr, u64 end_addr)
{
	return ddr_sec_cfg_for_feature(start_addr, end_addr, DDR_SEC_SION);
}

/* addr should be phy_addr  */
/*
	return 1 is secure
	return 0 is unsecure
*/
unsigned int is_sec_addr(u64 start_addr, u64 end_addr)
{
	return ddr_sec_check_for_feature(start_addr, end_addr, DDR_SEC_SION);;
}
/******************************************************/
/*ddr sec cfg for feature*/
/******************************************************/
int ddr_sec_cfg_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id)
{
	int ret = ERROR;

	if (OK != pthread_mutex_lock(&g_sec_pthread_lock)) {
		PRINT_ERROR("cfg:Wait lock_flag failed!\n");
		return ret;
	}

	switch (feature_id)
	{
#ifdef CONFIG_HISI_DDR_SEC_IDENTIFICATION
		case DDR_SEC_EID:
			ret = ddr_sec_cfg_for_identification(start_addr, end_addr);
			break;
#endif
#ifdef CONFIG_HISI_DDR_SEC_HIFI_RESET
		case DDR_SEC_HIFI_RESET:
			ret = ddr_sec_cfg_for_hifi_reset(start_addr, end_addr);
			break;
#endif
		case DDR_SEC_SION:
			ret = ddr_sec_cfg_for_sion(start_addr, end_addr);
			break;
#ifdef CONFIG_HISI_DDR_SEC_TUI
		case DDR_SEC_TUI:
			ret = ddr_sec_cfg_for_tui(start_addr, end_addr);
			break;
#endif
		default:
			PRINT_ERROR("ddr_sec_cfg:error feature!\n");
			break;
	}

	if (OK != pthread_mutex_unlock(&g_sec_pthread_lock)) {
		ret = ERROR;
		PRINT_ERROR("cfg:Release lock_flag failed!\n");
	}
	return ret;
}

/******************************************************/
/*ddr sec clean for feature*/
/******************************************************/
int ddr_sec_clean_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id)
{
	int ret = ERROR;

	if (OK != pthread_mutex_lock(&g_sec_pthread_lock)) {
		PRINT_ERROR("clean:Wait lock_flag failed!\n");
		return ret;
	}

	switch (feature_id)
	{
#ifdef CONFIG_HISI_DDR_SEC_IDENTIFICATION
		case DDR_SEC_EID:
			ret = ddr_sec_clean_for_identification(start_addr, end_addr);
			break;
#endif
#ifdef CONFIG_HISI_DDR_SEC_HIFI_RESET
		case DDR_SEC_HIFI_RESET:
			ret = ddr_sec_clean_for_hifi_reset(start_addr, end_addr);
			break;
#endif
		case DDR_SEC_SION:
			ret = ddr_sec_clean_for_sion(start_addr, end_addr);
			break;
#ifdef CONFIG_HISI_DDR_SEC_TUI
		case DDR_SEC_TUI:
			ret = ddr_sec_clean_for_tui(start_addr, end_addr);
			break;
#endif
		default:
			PRINT_ERROR("ddr_sec_clean:error feature!\n");
			break;
	}

	if (OK != pthread_mutex_unlock(&g_sec_pthread_lock)) {
		ret = ERROR;
		PRINT_ERROR("clean:Release lock_flag failed!\n");
	}
	return ret;
}
/******************************************************/
/*ddr sec check for feature*/
/******************************************************/
int ddr_sec_check_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id){
	int ret = ERROR;

	if (OK != pthread_mutex_lock(&g_sec_pthread_lock)) {
		PRINT_ERROR("check:Wait lock_flag failed!\n");
		return ret;
	}

	switch (feature_id)
	{
		case DDR_SEC_SION:
			ret = ddr_sec_check_for_sion(start_addr, end_addr);
			break;
#ifdef CONFIG_HISI_DDR_SEC_TUI
		case DDR_SEC_TUI:
			ret = ddr_sec_check_for_tui(start_addr, end_addr);
			break;
#endif
		default:
			PRINT_ERROR("check, error feature, feature_id:%d!\n", feature_id);
			break;
	}

	if (OK != pthread_mutex_unlock(&g_sec_pthread_lock)) {
		ret = ERROR;
		PRINT_ERROR("check:Release lock_flag failed!\n");
	}
	return ret;
}

static int ddr_sec_cfg_all_feature(enum SEC_FEATURE feature_id, DDR_CFG_TYPE ddr_cfg_type, u64 start_addr, u64 end_addr)
{
	int ret = ERROR;

	switch (feature_id) {
		case DDR_SEC_EID:
		case DDR_SEC_HIFI_RESET:
			if (ddr_cfg_type == DDR_SET_SEC) {
				ret = ddr_sec_cfg_for_feature(start_addr, end_addr, feature_id);
			} else if (ddr_cfg_type == DDR_UNSET_SEC) {
				ret = ddr_sec_clean_for_feature(start_addr, end_addr, feature_id);
			} else {
				PRINT_ERROR("wrong ddr_cfg_type:%d! feature:%d\n", ddr_cfg_type, feature_id);
				ret = ERROR;
			}
			break;
		case DDR_SEC_TUI:
			if (ddr_cfg_type == DDR_SET_SEC) {
				ret = ddr_sec_cfg_for_tui(start_addr, end_addr);
			} else if (ddr_cfg_type == DDR_UNSET_SEC) {
				ret = ddr_sec_clean_for_tui(start_addr, end_addr);
			} else if (ddr_cfg_type == DDR_CHECK_SEC) {
				ret = ddr_sec_check_for_tui(start_addr, end_addr);
			} else {
				PRINT_ERROR("wrong ddr_cfg_type:%d! feature:%d\n", ddr_cfg_type, feature_id);
				ret = ERROR;
			}
			break;
		case DDR_SEC_SION:
			if (ddr_cfg_type == DDR_SET_SEC) {
				ret = mddrc_sec_cfg(start_addr, end_addr);
			} else if (ddr_cfg_type == DDR_UNSET_SEC) {
				ret = mddrc_sec_clean(start_addr, end_addr);
			} else if (ddr_cfg_type == DDR_CHECK_SEC) {
				ret = (int)is_sec_addr(start_addr, end_addr);
			} else {
				PRINT_ERROR("wrong ddr_cfg_type:%d! feature:%d\n", ddr_cfg_type, feature_id);
				ret = ERROR;
			}
			break;
		case DDR_SEC_FACE:
			ret = OK;
			break;
		default:
			PRINT_ERROR("ddr_sec_cfg:error feature:%d\n", feature_id);
			ret = ERROR;
			break;
	}

	return ret;
}

int ddr_sec_cfg(struct sglist *sglist, int feature_id, int ddr_cfg_type)
{
	u64 start_addr, end_addr;
	int ret = ERROR;
	u32 info_num;
	u32 error_flag = 0;

	if (sglist == NULL) {
		PRINT_ERROR("sglist is null\n");
		return ERROR;
	}

	if (sglist->infoLength == 0) {
		PRINT_ERROR("Warning:sglist infoLength is 0\n");
		return ERROR;
	}

	for (info_num = 0; info_num < sglist->infoLength; info_num++) {
		start_addr = sglist->info[info_num].phys_addr;
		end_addr = start_addr + (u64)(sglist->info[info_num].npages) * (u64)PAGE_SIZE;
		ret = ddr_sec_cfg_all_feature(feature_id, ddr_cfg_type, start_addr, end_addr);
		if (ddr_cfg_type != DDR_CHECK_SEC && ret != OK) {
			error_flag = 1;
			break;
		} else if (ddr_cfg_type == DDR_CHECK_SEC && ret != SEC_ADDR) {
			error_flag = 1;
			break;
		}
	}

	if (error_flag == 1) {
		return ERROR;
	}

	return OK;
}
int check_sglist_pid(struct sglist *sglist, int pid)
{
	(void)sglist;
	(void)pid;
	return 0;
}
int check_unsec_sglist(struct sglist *sglist)
{
	(void)sglist;
	return 0;
}

/*ddr sec init*/
int sec_region_init(void)
{
	unsigned int i;
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif
	for (i = 0; i < ASI_NUM_MAX; i++) {
		g_rgn_num[i] = get_rgn_num_max(i);
	}
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif
	(void)memset_s(g_sion_sec_rgn, sizeof(g_sion_sec_rgn), 0, sizeof(g_sion_sec_rgn));
#ifdef CONFIG_HISI_DDR_SEC_TUI
	(void)memset_s(g_tui_sec_rgn, sizeof(g_tui_sec_rgn), 0, sizeof(g_tui_sec_rgn));
#endif
	return OK;
}
/******************************************************/
