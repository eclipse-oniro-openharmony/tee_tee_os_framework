/*************************************************************
*��  ��  ��  ��:	sec_region.c
*
*��  ��  ��  ��:	sec_region.c
*
*��  ��  ��  ��:	 w00294303
*
*��  ��  ʱ  ��:	2017-03-08
*************************************************************/

/**********************************************************
 ͷ�ļ�
**********************************************************/
#include <stdint.h>
#include <pthread.h>
#include <dynion.h> // TEE_PAGEINFO
#include <register_ops.h> // readl
#include "mem_page_ops.h"
#include "tee_log.h"
#include "tee_defines.h"
#include "securec.h"
#include "sec_region.h"
#include <sec_region_ops.h>

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
#include "hisi_ddr_autofsgt_proxy_secure_os.h"
#endif

/**********************************************************
 ȫ�ֱ���
**********************************************************/
static unsigned int g_rgn_num[ASI_NUM_MAX];
static SEC_RGN_CFG g_ion_sec_rgn[SEC_RGN_ION_RESERVED_NUM];
#ifdef CONFIG_HISI_DDR_SEC_IDENTIFICATION
static SEC_RGN_CFG g_identification_sec_rgn = {0};
#endif
#ifdef CONFIG_HISI_DDR_SEC_HIFI_RESET
static SEC_RGN_CFG g_hifi_reset_sec_rgn = {0};
#endif
pthread_mutex_t g_sec_pthread_lock = PTHREAD_MUTEX_INITIALIZER;
/**********************************************************
 ��
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

#define sec_ion_rgn_use_now(rgn)	(SEC_RGN_ION_RESERVED - (rgn))

/**********************************************************
 ����
**********************************************************/
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
static unsigned int get_rgn_num_max(unsigned int asi_num)
{
	u32 asi_rtl_inf2 = 0x1F & readl((u32)SOC_DMSS_ASI_RTL_INF2_ADDR(REG_BASE_DMSS, asi_num));
	if (!asi_rtl_inf2) {
		return 32;
	}
	return (asi_rtl_inf2);
}
#else
static unsigned int get_rgn_num_max(unsigned int asi_num)
{
	SOC_DMSS_ASI_RTL_INF2_UNION asi_rtl_inf2;
	asi_rtl_inf2.value = readl((u32)SOC_DMSS_ASI_RTL_INF2_ADDR(REG_BASE_DMSS, asi_num));
	return (asi_rtl_inf2.reg.rtl_sec_rgn_num);
}
#endif
/*****************************************************
	���rgn �Ƿ����
	asi_num ��rgn_num �����Բ������ֵ
	��rgn �������Ѿ���ʹ��
*******************************************/
static int check_rgn_usable(unsigned int asi_num, unsigned int rgn_num)
{
	int ret = OK;
	unsigned int value;

	MDDRC_SEC_CHECK_SECANDRGN(ret, asi_num, rgn_num);

	value = readl(SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
	if ((value>>SOC_DMSS_ASI_SEC_RGN_MAP0_rgn_en_START)&0x1) {
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
		PRINT_ERROR("[%s]_%d: err!\n", __func__, __LINE__);
		PRINT_DEBUG("[%s]_%d: asi%d rgn%d addr err! start:%llx,end:%llx;\n", __func__, __LINE__, asi_num, rgn_num,
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
	���region
	asi_num �� rgn_num�ĺϷ���������ж�
*/
static inline void sec_region_clean(unsigned int asi_num, unsigned int rgn_num)
{
	unsigned int value;

	value = readl((u32)SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(REG_BASE_DMSS, rgn_num, asi_num));
	writel((~(1UL<<SOC_DMSS_ASI_SEC_RGN_MAP0_rgn_en_START)) & value,
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
		if ((1<<set_asi)&asi_mask) {
			ret = sec_region_cfg(set_asi, g_rgn_num[set_asi] - reserved_reg, sec_rgn_cfg);
			if (ret) {
				PRINT_ERROR("sec_region_cfg fail\n");
				break;
			}
		}
	}

	/* if set sec region error */
	for (clean_asi = 0; (OK != ret) && (clean_asi < set_asi); clean_asi++) {
		if ((1<<clean_asi)&asi_mask) {
			sec_region_clean(clean_asi, g_rgn_num[clean_asi] - reserved_reg);
		}
	}

	return ret;
}

static unsigned int find_region_by_addr(u64 start_addr, u64 end_addr)
{
	unsigned int i;
	for (i = 0; i < SEC_RGN_ION_RESERVED_NUM; i++) {
		if ((start_addr == g_ion_sec_rgn[i].start_addr)&&(end_addr == g_ion_sec_rgn[i].end_addr)) {
			return i;
		}
	}

	return INVALID_REGION_INDEX;
}
static unsigned int sec_get_unused_region()
{
	unsigned int i;
	for (i = 0; i < SEC_RGN_ION_RESERVED_NUM; i++) {
		if (0 == g_ion_sec_rgn[i].rgn_en) {
			return i;
		}
	}
	return INVALID_REGION_INDEX;
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
			/*rgn_start~rgn_end ǰ�պ�*/
			if ((start_addr >= rgn_start && start_addr < rgn_end)
				|| (end_addr > rgn_start && end_addr <= rgn_end)
				|| (rgn_start < rgn_end && start_addr <= rgn_start && end_addr >= rgn_end))
			{
				PRINT_DEBUG("check addr start 0x%llx, end 0x%llx\n", start_addr, end_addr);
				PRINT_DEBUG("ASI %d rgn %d   0x%x   0x%x   0x%x   0x%x\n", asi_num, rgn_num, rgn_map0.value, rgn_map1.value,
					readl((u32)SOC_DMSS_ASI_SEC_MID_WR_ADDR(REG_BASE_DMSS, rgn_num, asi_num)),
					readl((u32)SOC_DMSS_ASI_SEC_MID_RD_ADDR(REG_BASE_DMSS, rgn_num, asi_num)));
				return ERROR;	/*is covered by region*/
			}
		}
	}

	return OK;	/*is not covered by region*/
}

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
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	if (ERROR == is_not_covered_by_region(start_addr, end_addr))
	{
		PRINT_ERROR("identification addr has been covered!\n");
		return ERROR;
	}

	/*port vdec isp_dss ivp forbid*/
	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;
	cfg_data.mid_rd = FORBID_MID;
	cfg_data.mid_wr = FORBID_MID;
	cfg_data.attri = RW_FORBID;
	ret = sec_region_cfg_mask(VDEC_ASI_MASK | ISP_DSS_ASI_MASK | IVP32_ASI_MASK, SEC_RGN_IDENTIFICATION_RESERVED, &cfg_data);
	CHECK_RET(ret);

	/*port CPU SW\SR*/
	cfg_data.mid_rd = CPU_ALL;
	cfg_data.mid_wr = CPU_ALL;
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(CPU_GPU_ASI_MASK, SEC_RGN_IDENTIFICATION_RESERVED, &cfg_data);
	CHECK_RET(ret);

	/*port subsys SW\SR*/
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
	cfg_data.mid_rd = (1 << DJTAG_M_MID) | (1 << SEC_S_MID) | (1 << DMAC_MID);
	cfg_data.mid_wr = (1 << DJTAG_M_MID) | (1 << SEC_S_MID) | (1 << DMAC_MID);
#else
	cfg_data.mid_rd = (1 << DJTAG_M_MID) | (1 << CC712_MID) | (1 << DMAC_MID);
	cfg_data.mid_wr = (1 << DJTAG_M_MID) | (1 << CC712_MID) | (1 << DMAC_MID);
#endif
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(SUBSYS_ASI_MASK, SEC_RGN_IDENTIFICATION_RESERVED, &cfg_data);
	CHECK_RET(ret);

	g_identification_sec_rgn.rgn_en = 1;
	g_identification_sec_rgn.start_addr = start_addr;
	g_identification_sec_rgn.end_addr = end_addr;

err_proc:

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
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
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_CLRSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	/*clean sec region*/
	for (i = 1; i < ASI_NUM_MAX; i++) {
		sec_region_clean(i, g_rgn_num[i] - SEC_RGN_IDENTIFICATION_RESERVED);
	}

	g_identification_sec_rgn.rgn_en = 0;
	g_identification_sec_rgn.start_addr = 0;
	g_identification_sec_rgn.end_addr = 0;


#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_CLRSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return OK;
}
#endif

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
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	if (ERROR == is_not_covered_by_region(start_addr, end_addr))
	{
		PRINT_ERROR("hifi reset addr has been covered!\n");
		return ERROR;
	}

	/*port vdec isp_dss ivp forbid*/
	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;
	cfg_data.mid_rd = FORBID_MID;
	cfg_data.mid_wr = FORBID_MID;
	cfg_data.attri = RW_FORBID;
	ret = sec_region_cfg_mask(VDEC_ASI_MASK | ISP_DSS_ASI_MASK | IVP32_ASI_MASK, SEC_RGN_HIFI_REBOOT_RESERVED, &cfg_data);
	CHECK_RET(ret);

	/*port CPU SW\SR*/
	cfg_data.mid_rd = CPU_ALL;
	cfg_data.mid_wr = CPU_ALL;
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(CPU_GPU_ASI_MASK, SEC_RGN_HIFI_REBOOT_RESERVED, &cfg_data);
	CHECK_RET(ret);

	/*port subsys SW\SR*/
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260) || \
     (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW)
	cfg_data.mid_rd = (1 << SEC_S_MID);
	cfg_data.mid_wr = (1 << SEC_S_MID);
#else
	cfg_data.mid_rd = (1 << CC712_MID);
	cfg_data.mid_wr = (1 << CC712_MID);
#endif
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(SUBSYS_ASI_MASK, SEC_RGN_HIFI_REBOOT_RESERVED, &cfg_data);
	CHECK_RET(ret);

	g_hifi_reset_sec_rgn.rgn_en = 1;
	g_hifi_reset_sec_rgn.start_addr = start_addr;
	g_hifi_reset_sec_rgn.end_addr = end_addr;

err_proc:

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
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
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_CLRSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	/*clean sec region*/
	for (i = 1; i < ASI_NUM_MAX; i++) {
		sec_region_clean(i, g_rgn_num[i] - SEC_RGN_HIFI_REBOOT_RESERVED);
	}

	g_hifi_reset_sec_rgn.rgn_en = 0;
	g_hifi_reset_sec_rgn.start_addr = 0;
	g_hifi_reset_sec_rgn.end_addr = 0;


#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_CLRSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return OK;
}
#endif

/******************************************************/
int mddrc_sec_clean(u64 start_addr, u64 end_addr)
{
	unsigned int rgn_index;
	unsigned int i;
	int ret = OK;

	if (OK != pthread_mutex_lock(&g_sec_pthread_lock)) {
		PRINT_ERROR("%s:Wait lock_flag failed!\n", __func__);
		return ERROR;
	}

	PRINT_INFO("++mddrc_sec_clean++ start 0x%llx, end 0x%llx\n", start_addr, end_addr);
	rgn_index = find_region_by_addr(start_addr, end_addr);

	if (rgn_index >= SEC_RGN_ION_RESERVED_NUM) {
		ret = ERROR;
		PRINT_DEBUG("find_region_by_addr fail start 0x%llx, end 0x%llx\n", start_addr, end_addr);
		goto err_proc;
	}

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_CLRSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif


	/*clean sec region*/
	for (i = 1; i < ASI_NUM_MAX; i++) {
		sec_region_clean(i, g_rgn_num[i] - sec_ion_rgn_use_now(rgn_index));
	}

	g_ion_sec_rgn[rgn_index].rgn_en = 0;
	g_ion_sec_rgn[rgn_index].start_addr = 0;
	g_ion_sec_rgn[rgn_index].end_addr = 0;


#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_CLRSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif

err_proc:
	if (OK != pthread_mutex_unlock(&g_sec_pthread_lock)) {
		ret = ERROR;
		PRINT_ERROR("%s:Release lock_flag failed!\n", __func__);
	}
	return ret;
}


int mddrc_sec_cfg(u64 start_addr, u64 end_addr)
{
	PRINT_INFO("++mddrc_sec_cfg++ start 0x%llx, end 0x%llx\n", start_addr, end_addr);
	unsigned int rgn_index;
	int ret = ERROR;
	SEC_RGN_CFG cfg_data;

	if (OK != pthread_mutex_lock(&g_sec_pthread_lock)) {
		PRINT_ERROR("%s:Wait lock_flag failed!\n", __func__);
		return ret;
	}

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	if (ERROR == is_not_covered_by_region(start_addr, end_addr)){
		PRINT_ERROR("mddrc_sec_cfg addr has been covered!\n");
		goto err_proc;
	}
	(void)memset_s(&cfg_data, sizeof(SEC_RGN_CFG), 0, sizeof(SEC_RGN_CFG));

	rgn_index = sec_get_unused_region();
	if (rgn_index >= SEC_RGN_ION_RESERVED_NUM) {
		PRINT_ERROR("get_unused_region fail\n");
		goto err_proc;
	}

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260) || \
	(TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW)
	/*port vdec ivp forbid*/
	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;
	cfg_data.mid_rd = FORBID_MID;
	cfg_data.mid_wr = FORBID_MID;
	cfg_data.attri = RW_FORBID;

	ret = sec_region_cfg_mask(VDEC_ASI_MASK|IVP32_ASI_MASK, (sec_ion_rgn_use_now(rgn_index)), &cfg_data);
	CHECK_RET(ret);
#else
	/*port vdec ics PART SW/SR*/
	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;
	cfg_data.mid_rd = (1 << ICS_MID) | (1 << ICS2_MID);
	cfg_data.mid_wr = (1 << ICS_MID) | (1 << ICS2_MID);
	cfg_data.attri = SEC_WR|SEC_RD;

	ret = sec_region_cfg_mask(VDEC_ASI_MASK, (sec_ion_rgn_use_now(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port ivp SR/SW*/
	cfg_data.mid_rd = ALL_MID;
	cfg_data.mid_wr = ALL_MID;
	cfg_data.attri = SEC_WR|SEC_RD;

	ret = sec_region_cfg_mask(IVP32_ASI_MASK, (sec_ion_rgn_use_now(rgn_index)), &cfg_data);
	CHECK_RET(ret);
#endif

	/*port isp_dss SW\SR*/
	cfg_data.mid_rd = ALL_MID;
	cfg_data.mid_wr = ALL_MID;
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(ISP_DSS_ASI_MASK, (sec_ion_rgn_use_now(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port CPU SW\SR*/
	cfg_data.mid_rd = CPU_ALL;
	cfg_data.mid_wr = CPU_ALL;
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(CPU_GPU_ASI_MASK, (sec_ion_rgn_use_now(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	/*port subsys sec_s SW\SR*/
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260) || \
     (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW)
	cfg_data.mid_rd = 1<<SEC_S_MID;
	cfg_data.mid_wr = 1<<SEC_S_MID;
#else
	cfg_data.mid_rd = 1<<CC712_MID;
	cfg_data.mid_wr = 1<<CC712_MID;
#endif
	cfg_data.attri = SEC_WR|SEC_RD;
	ret = sec_region_cfg_mask(SUBSYS_ASI_MASK, (sec_ion_rgn_use_now(rgn_index)), &cfg_data);
	CHECK_RET(ret);

	g_ion_sec_rgn[rgn_index].rgn_en = 1;
	g_ion_sec_rgn[rgn_index].start_addr = start_addr;
	g_ion_sec_rgn[rgn_index].end_addr = end_addr;

err_proc:

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif

	if (OK != pthread_mutex_unlock(&g_sec_pthread_lock)) {
		ret = ERROR;
		PRINT_ERROR("%s:Release lock_flag failed!\n", __func__);
	}
	return ret;
}


/* addr should be phy_addr  */
/*
	return 1 is secure
	return 0 is unsecure
*/
unsigned int is_sec_addr(u64 start_addr, u64 end_addr)
{
	u32 i, loop_flag;
	int ret = UNSEC_ADDR;

	if(start_addr >= end_addr){
		PRINT_ERROR("start_addr is beyond end_addr!\n");
		return ret;
	}

	if (OK != pthread_mutex_lock(&g_sec_pthread_lock)) {
			PRINT_ERROR("%s:Wait lock_flag failed!\n", __func__);
			return ret;
		}

	do{
		loop_flag = 0;
		for (i = 0; i < SEC_RGN_ION_RESERVED_NUM; i++) {
			if ((start_addr >= g_ion_sec_rgn[i].start_addr) && (start_addr < g_ion_sec_rgn[i].end_addr)) {
				if(end_addr > g_ion_sec_rgn[i].end_addr){
					start_addr = g_ion_sec_rgn[i].end_addr;
					loop_flag = 1;
					break;
				}
				ret = SEC_ADDR;/*secure*/
				goto err_proc;
			}
		}
	}while (loop_flag);

err_proc:
	if (OK != pthread_mutex_unlock(&g_sec_pthread_lock)) {
		ret = 0;
		PRINT_ERROR("%s:Release lock_flag failed!\n", __func__);
	}
	return ret;
}

/******************************************************/
#ifdef CONFIG_HISI_DDR_SEC_CFC
int kernel_read_only_enable(u64 start_addr, u64 end_addr)
{
	unsigned int i, cpu_asi = 6, rgn_index;
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

	/*port 6\7\9\10 CPU SW\SR*/
	cfg_data.rgn_en = 1;
	cfg_data.start_addr = start_addr;
	cfg_data.end_addr = end_addr;
	cfg_data.mid_rd = CPU_ALL;
	cfg_data.mid_wr = CPU_ALL;
	cfg_data.attri = SEC_WR|SEC_RD|UNSEC_RD;

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif
	for (i = 0; i < ASI_NUM_MAX; i++) {
		g_rgn_num[i] = get_rgn_num_max(i);
	}

	/* if kernel protect open*/
	rgn_index = g_rgn_num[cpu_asi]-SEC_RGN_KERNEL_PROTECT_RESERVED;
	if (check_rgn_usable(cpu_asi, rgn_index)) {
		sec_rgn_map1 = (volatile SOC_DMSS_ASI_SEC_RGN_MAP1_UNION *)
		((unsigned long)SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(REG_BASE_DMSS, rgn_index, cpu_asi));

		allow_addr = (u64)(sec_rgn_map1->reg.rgn_top_addr + 1)<<SEC_RGN_ADDR_SHIFT;

		if (start_addr < allow_addr) {
			sec_rgn_map1->reg.rgn_top_addr = (start_addr-1)>>SEC_RGN_ADDR_SHIFT;
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

	ret = sec_region_cfg_mask(CPU_GPU_ASI_MASK, SEC_RGN_KERNEL_READ_ONLY_RESERVED, &cfg_data);
err_proc:
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return ret;
}
#endif

#ifdef CONFIG_HISI_DDR_SEC_CORESIGHT
/******************************************************/
/**for top coresght read*/
/******************************************************/
int sec_region_coresight_enable(u32 enable_size)
{
	int ret;
	SEC_RGN_CFG cfg_data;
	(void)memset_s(&cfg_data, sizeof(SEC_RGN_CFG), 0, sizeof(SEC_RGN_CFG));

	if ((enable_size > TOP_CORESIGHT_PHYMEM_SIZE) || (enable_size & SEC_RGN_ADDR_MASK)) {
		return ERROR;
	}

	cfg_data.rgn_en = 1;
	cfg_data.start_addr = TOP_CORESIGHT_PHYMEM_END - enable_size;
	cfg_data.end_addr = TOP_CORESIGHT_PHYMEM_END;
	cfg_data.mid_rd = (1<<TOP_CSSYS_MID);
	cfg_data.mid_wr = (1<<TOP_CSSYS_MID);
	cfg_data.attri = UNSEC_WR;

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif
	/*port8 open top_cssys uswr*/
	ret = sec_region_cfg_mask(SUBSYS_ASI_MASK, SEC_RGN_TOP_CORESIGHT_RESERVED, &cfg_data);

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif
	return ret;
}
#endif

/******************************************************/
/*ddr sec cfg for feature*/
/******************************************************/
int ddr_sec_cfg_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id)
{
	int ret = ERROR;

	PRINT_DEBUG("ddr_sec_cfg start 0x%llx, end 0x%llx, feature%d\n", start_addr, end_addr, feature_id);

	if (OK != pthread_mutex_lock(&g_sec_pthread_lock)) {
		PRINT_ERROR("%s:Wait lock_flag failed!\n", __func__);
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
		case DDR_SEC_TUI:
		default:
			PRINT_ERROR("ddr_sec_cfg:error feature!\n");
			break;
	}

	if (OK != pthread_mutex_unlock(&g_sec_pthread_lock)) {
		ret = ERROR;
		PRINT_ERROR("%s:Release lock_flag failed!\n", __func__);
	}
	return ret;
}

/******************************************************/
/*ddr sec clean for feature*/
/******************************************************/
int ddr_sec_clean_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id)
{
	int ret = ERROR;

	PRINT_DEBUG("ddr_sec_clean start 0x%llx, end 0x%llx, feature%d\n", start_addr, end_addr, feature_id);

	if (OK != pthread_mutex_lock(&g_sec_pthread_lock)) {
		PRINT_ERROR("%s:Wait lock_flag failed!\n", __func__);
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
		case DDR_SEC_TUI:
		default:
			PRINT_ERROR("ddr_sec_clean:error feature!\n");
			break;
	}

	if (OK != pthread_mutex_unlock(&g_sec_pthread_lock)) {
		ret = ERROR;
		PRINT_ERROR("%s:Release lock_flag failed!\n", __func__);
	}

	return ret;
}

int ddr_sec_cfg_all_feature(enum SEC_FEATURE feature_id, DDR_CFG_TYPE ddr_cfg_type, u64 start_addr, u64 end_addr)
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
		PRINT_ERROR("Warning: sglist infoLength is 0\n");
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

int check_sglist_pid(struct sglist *sglist, int feature_id)
{
	(void)sglist;
	(void)feature_id;
	return OK;
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

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	for (segment_num = 0; segment_num < (sglist->infoLength); segment_num++) {
		segment_info = (TEE_PAGEINFO *)(sglist->info + segment_num);
		segment_start_addr = segment_info->phys_addr;
		segment_end_addr = segment_start_addr + (u64)segment_info->npages * (u64)PAGE_SIZE;
		ret = is_not_covered_by_region(segment_start_addr, segment_end_addr);
		if (ret != OK) {
			PRINT_ERROR("check_unsec_sglist fail\n");
			PRINT_DEBUG("sglist have sec addr, s_s_addr:0x%llx, s_e_addr:0x%llx\n", segment_start_addr, segment_end_addr);
			goto err_proc;
		}
	}

err_proc:
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif

	return ret;
}



/*ddr sec init*/
int sec_region_init(void)
{
	unsigned int i;
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif
	for (i = 0; i < ASI_NUM_MAX; i++) {
		g_rgn_num[i] = get_rgn_num_max(i);
	}
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif
	(void)memset_s(g_ion_sec_rgn, sizeof(g_ion_sec_rgn), 0, sizeof(g_ion_sec_rgn));
	return OK;
}
/******************************************************/
