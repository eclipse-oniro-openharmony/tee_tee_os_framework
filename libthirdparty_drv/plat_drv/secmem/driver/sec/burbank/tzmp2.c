/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mpu protect function of the secure os
 * Author: bujing
 * Create: 2020-08-01
 */

#include "tzmp2.h"
#include <mem_ops_ext.h>
#include <dynion.h>
#include "drv_module.h"
#include "mem_ops.h"
#include "mem_page_ops.h"
#include "register_ops.h"
#include <tzmp2_ops.h>
#include "sre_log.h"
#include <pthread.h>
#include <ddr_define.h>
#include <soc_acpu_baseaddr_interface.h>
#include <soc_ddrc_dmc_interface.h>
#include <soc_dmss_interface.h>
#include <ddr_sec_feature.h>
#ifdef CONFIG_HISI_DDR_AUTO_FSGT
#include <hisi_ddr_autofsgt_proxy_burbank.h>
#endif

static u32 g_mpu_seccfg_granularity_size = 0;
static u64 g_mpu_seccfg_addr_zone = 0;
pthread_mutex_t g_tzmp2_pthread_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef CONFIG_HISI_DDR_CA_RD
static u32 g_ca_rd_cfg_flag = 0;
pthread_mutex_t g_ca_rd_pthread_lock = PTHREAD_MUTEX_INITIALIZER;

s32 ddrc_ca_rd_cfg(s32 ca_rd_enable)
{
	s32 ret = OK;
	s32 i, loop_cnt;
	volatile SOC_DDRC_DMC_DDRC_CFG_CA_UNION *ddrc_cfg_ca = NULL;
	volatile SOC_DDRC_DMC_DDRC_CHG_CAEPS_UNION *ddrc_chg_caeps = NULL;

	if (pthread_mutex_lock(&g_ca_rd_pthread_lock) != OK) {
		tloge("check:Wait lock_flag failed!\n");
		return ERROR;
	}

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CA_RD_CFG, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	for (i = 0; i < CHANNEL_MAX_NUM; i++) {
		ddrc_cfg_ca = (volatile SOC_DDRC_DMC_DDRC_CFG_CA_UNION *)SOC_DDRC_DMC_DDRC_CFG_CA_ADDR(DDR_REG_DMC(i));
		ddrc_chg_caeps = (volatile SOC_DDRC_DMC_DDRC_CHG_CAEPS_UNION *)SOC_DDRC_DMC_DDRC_CHG_CAEPS_ADDR(DDR_REG_DMC(i));

		ddrc_chg_caeps->reg.oneop_chg_caeps = 0x1;

		if (ca_rd_enable) {
			ddrc_cfg_ca->reg.ca_rd_en = CA_RD_ENABLE;
			ddrc_cfg_ca->reg.ca_wr_en = CA_WR_ENABLE;
		} else {
			ddrc_cfg_ca->reg.ca_rd_en = CA_RD_DISABLE;
			ddrc_cfg_ca->reg.ca_wr_en = CA_WR_DISABLE;
		}

		loop_cnt = DDR_CA_CFG_CHECK_CNT;
		do {
			if (ddrc_chg_caeps->reg.oneop_chg_ca_ok != 0)
				break;
			loop_cnt--;
		} while (loop_cnt > 0);
		if (loop_cnt <= 0) {
			tloge("fail to change ddr ca encrypt, ddrc_num = %d\n", i);
			ret = ERROR;
			goto error_proc;
		}
	}

	if (ca_rd_enable == DIS_CA_RD) {
		g_ca_rd_cfg_flag = 0;
		tlogi("ca_rd_en = %d, disable ok \n", ddrc_cfg_ca->reg.ca_rd_en);
	}

error_proc:
#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CA_RD_CFG, DDR_AUTOFSGT_LOGIC_EN);
#endif

	if (pthread_mutex_unlock(&g_ca_rd_pthread_lock) != OK) {
		ret = ERROR;
		tloge("cfg:Release lock_flag failed!\n");
	}
	return ret;
}
#endif

static void cpu_addr_shift(u64 *phys)
{
	u64 phys_addr_start = *phys;
	u32 addr_shift_mode = (readl(SOC_DMSS_ASI_ADDR_SHIFT_ADDR(SOC_ACPU_DMSS_BASE_ADDR, CPU_ASI_NUM))) & ADDR_SHIFT_MODE_MASK;

	tlogi("[%s]addr_shift_mode is %d\n", __func__, addr_shift_mode);

	if (addr_shift_mode == ADDR_SHIFT_MODE_1 && phys_addr_start >= ADDR_SHIFT_MODE_1_START_ADDR &&
		phys_addr_start < ADDR_SHIFT_MODE_1_END_ADDR)
		*phys = phys_addr_start - ADDR_SHIFT_MODE_1_START_ADDR + DDR_SIZE_3G512M;
	else if (addr_shift_mode == ADDR_SHIFT_MODE_2 && phys_addr_start >= ADDR_SHIFT_MODE_2_START_ADDR &&
		phys_addr_start < ADDR_SHIFT_MODE_2_END_ADDR)
		*phys = phys_addr_start - ADDR_SHIFT_MODE_2_START_ADDR + DDR_SIZE_3G512M;
}

static s32 tzmp2_cfg_process(u64 phys, u32 size, enum mpu_cfg_type mpu_cfg_type)
{
	u32 start_reg, bit_length_total, bit_length_reg, reg_value, reg_start_bit, loop_flag;

	/* configure mpu ram, 1bit represent 64K/128K/256K */
	start_reg = (phys / g_mpu_seccfg_granularity_size) / REG_BIT_NUM;
	reg_start_bit = (phys / g_mpu_seccfg_granularity_size) % REG_BIT_NUM;
	bit_length_total = size / g_mpu_seccfg_granularity_size;
	tlogi("s_r %d, r_s_b %d, b_l_t %d\n", start_reg, reg_start_bit, bit_length_total);

	do {
		loop_flag = 0;
		if ((reg_start_bit + bit_length_total) > REG_BIT_NUM) {
			bit_length_reg = REG_BIT_NUM - reg_start_bit;
			loop_flag = 1;
		} else {
			bit_length_reg = bit_length_total;
		}

		reg_value = readl(SOC_DMSS_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_BASE_ADDR, start_reg));
		if (mpu_cfg_type == MPU_SET_SEC) {
			reg_value |= VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length_reg), reg_start_bit);
			writel(reg_value, SOC_DMSS_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_BASE_ADDR, start_reg));
			tlogi("[MPU_SET_SEC]start_reg %d, reg_start_bit %d, bit_length_total %d\n", start_reg, reg_start_bit, bit_length_total);
			tlogi("[MPU_SET_SEC]reg_value 0x%x, mpu_addr 0x%x\n", reg_value, SOC_DMSS_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_BASE_ADDR, start_reg));
		} else if (mpu_cfg_type == MPU_UNSET_SEC) {
			reg_value &= ~(VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length_reg), reg_start_bit));
			writel(reg_value, SOC_DMSS_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_BASE_ADDR, start_reg));
			tlogi("[MPU_UNSET_SEC]start_reg %d, reg_start_bit %d, bit_length_total %d\n", start_reg, reg_start_bit, bit_length_total);
			tlogi("[MPU_UNSET_SEC]reg_value 0x%x, mpu_addr 0x%x\n", reg_value, SOC_DMSS_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_BASE_ADDR, start_reg));
		} else if(mpu_cfg_type == MPU_CHECK_SEC) {
			reg_value &= VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length_reg), reg_start_bit);
			if (reg_value != VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length_reg), reg_start_bit)) {
				tlogi("[MPU_CHECK_SEC]reg_value 0x%x, bit_length_reg 0x%x, reg_start_bit 0x%x\n", reg_value, bit_length_reg, reg_start_bit);
				return ERROR;
			}
		} else {
			tloge("wrong mpu_cfg_type\n");
			return ERROR;
		}

		if (loop_flag != 0) {
			start_reg++;
			reg_start_bit = 0;
			bit_length_total -= bit_length_reg;
		}
	} while (loop_flag != 0);

	return OK;
}

static s32 tzmp2_cfg(u64 phys, u32 size, enum mpu_cfg_type mpu_cfg_type)
{
	s32 ret = OK;

	if (pthread_mutex_lock(&g_tzmp2_pthread_lock) != OK) {
		tloge("check:Wait lock_flag failed!\n");
		return ERROR;
	}

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_TZMP2_CFG, DDR_AUTOFSGT_LOGIC_DIS);
#endif

#ifdef CONFIG_HISI_DDR_CA_RD
	if (mpu_cfg_type == MPU_SET_SEC && g_ca_rd_cfg_flag == 0) {
		if (ddrc_ca_rd_cfg(EN_CA_RD) != OK) {
			tloge("ddrc_ca_cfg ca_enable fail \n");
			ret = ERROR;
			goto error_proc;
		}
		g_ca_rd_cfg_flag = 1;
	}
#endif

	if (size % g_mpu_seccfg_granularity_size != 0) {
		tloge("size is not alignment with g_mpu_seccfg_granularity_size");
		ret = ERROR;
		goto error_proc;
	}

	cpu_addr_shift(&phys);
	tlogi("[%s]phys is 0x%llx, size is 0x%lx\n", __func__, phys, size);

	if (phys >= g_mpu_seccfg_addr_zone || size == 0 || (phys + (u64)size) >= g_mpu_seccfg_addr_zone) {
		tloge("phys addr beyond g_mpu_seccfg_addr_zone or size equal 0\n");
		ret = ERROR;
		goto error_proc;
	}

	if (tzmp2_cfg_process(phys, size, mpu_cfg_type) != OK) {
		tlogi("tzmp2_cfg_process failed!\n");
		ret = ERROR;
		goto error_proc;
	}

error_proc:
#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_TZMP2_CFG, DDR_AUTOFSGT_LOGIC_EN);
#endif

	if (pthread_mutex_unlock(&g_tzmp2_pthread_lock) != OK) {
		ret = ERROR;
		tloge("cfg:Release lock_flag failed!\n");
	}

	return ret;
}

s32 tzmp2_set_sec(u64 phys, u32 size)
{
	return tzmp2_cfg(phys, size, MPU_SET_SEC);
}

s32 tzmp2_unset_sec(u64 phys, u32 size)
{
	return tzmp2_cfg(phys, size, MPU_UNSET_SEC);
}

s32 tzmp2_check_sec(u64 phys, u32 size)
{
	return tzmp2_cfg(phys, size, MPU_CHECK_SEC);
}

int tzmp2_pro_cfg(struct sglist *sglist, enum SEC_FEATURE feature_id, DDR_CFG_TYPE ddr_cfg_type)
{
	(void)feature_id;
	int ret = OK;
	TEE_PAGEINFO *segment_info = NULL;
	u32 segment_num, segment_size;
	u64 segment_start_addr;

	for (segment_num = 0; segment_num < sglist->infoLength; segment_num++) {
		segment_info = (TEE_PAGEINFO *)(sglist->info + segment_num);
		segment_start_addr = segment_info->phys_addr;
		segment_size = segment_info->npages * PAGE_SIZE;
		switch (ddr_cfg_type) {
		case DDR_SET_SEC:
			ret = tzmp2_cfg(segment_start_addr, segment_size, MPU_SET_SEC);
			break;
		case DDR_UNSET_SEC:
			ret = tzmp2_cfg(segment_start_addr, segment_size, MPU_UNSET_SEC);
			break;
		case DDR_CHECK_SEC:
			ret = tzmp2_cfg(segment_start_addr, segment_size, MPU_CHECK_SEC);
			break;
		default:
			tloge("wrong ddr_cfg_type\n");
			return ERROR;
		}
	}

	return ret;
}

s32 tzmp2_init(void)
{
	u32 glb_mpu_cfg;

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_TZMP2_INIT, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	glb_mpu_cfg = readl(SOC_DMSS_GLB_MPU_CFG_ADDR(SOC_ACPU_DMSS_BASE_ADDR));

#ifdef CONFIG_HISI_DDR_AUTO_FSGT
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_TZMP2_INIT, DDR_AUTOFSGT_LOGIC_EN);
#endif

	switch (get_mpu_addr_zone(glb_mpu_cfg)) {
	case MPU_ADDR_ZONE_4G:
		g_mpu_seccfg_granularity_size = DDR_SIZE_64K;
		g_mpu_seccfg_addr_zone = DDR_SIZE_4G;
		break;
	case MPU_ADDR_ZONE_8G:
		g_mpu_seccfg_granularity_size = DDR_SIZE_128K;
		g_mpu_seccfg_addr_zone = DDR_SIZE_8G;
		break;
	case MPU_ADDR_ZONE_16G:
		g_mpu_seccfg_granularity_size = DDR_SIZE_256K;
		g_mpu_seccfg_addr_zone = DDR_SIZE_16G;
		break;
	case MPU_ADDR_ZONE_32G:
		g_mpu_seccfg_granularity_size = DDR_SIZE_512K;
		g_mpu_seccfg_addr_zone = DDR_SIZE_32G;
		break;
	default :
		tloge("tzmp2_init get mpu_addr_zone fail\n");
		return ERROR;
	}

	return OK;
}
