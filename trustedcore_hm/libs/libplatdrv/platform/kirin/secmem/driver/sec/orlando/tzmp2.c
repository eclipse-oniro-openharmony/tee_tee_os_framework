#include "drv_module.h"
#include "sre_log.h"
#include "mem_ops.h"
#include "mem_page_ops.h"
#include "tzmp2.h"
#include <pthread.h>
#include <tzmp2_ops.h>

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
#include <hisi_ddr_autofsgt_proxy_secure_os.h>
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
	s32 i, j, loop_cnt;
	volatile SOC_DDRC_DMC_DDRC_CFG_CA_UNION *ddrc_cfg_ca = NULL;
	volatile SOC_DDRC_DMC_DDRC_CHG_CAEPS_UNION* ddrc_chg_caeps = NULL;

	if (OK != pthread_mutex_lock(&g_ca_rd_pthread_lock)) {
		tloge("check:Wait lock_flag failed!\n");
		return ERROR;
	}

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	ddrc_cfg_ca = (volatile SOC_DDRC_DMC_DDRC_CFG_CA_UNION*)SOC_DDRC_DMC_DDRC_CFG_CA_ADDR(DDR_REG_DMC(0, 0));
	if(CA_WR_DISABLE == ddrc_cfg_ca->reg.ca_wr_en){
		tloge("Warning, ca_wr_en is disable!\n");
		goto error_proc;
	}

	for(i = 0; i < DDRC_NUM_MAX; i++){
		for(j = 0; j < DMC_NUM_MAX; j++){
			ddrc_cfg_ca = (volatile SOC_DDRC_DMC_DDRC_CFG_CA_UNION*)SOC_DDRC_DMC_DDRC_CFG_CA_ADDR(DDR_REG_DMC(i, j));
			ddrc_chg_caeps = (volatile SOC_DDRC_DMC_DDRC_CHG_CAEPS_UNION*)SOC_DDRC_DMC_DDRC_CHG_CAEPS_ADDR(DDR_REG_DMC(i, j));

			/*1、使能硬件一键加解密*/
			ddrc_chg_caeps->reg.oneop_chg_caeps = 0x1;

			/*2、使能或取消读解密*/
			if(ca_rd_enable){
				ddrc_cfg_ca->reg.ca_rd_en = CA_RD_ENABLE;
			}else{
				ddrc_cfg_ca->reg.ca_rd_en = CA_RD_DISABLE;
			}

			/*3、确认读解密改写成功*/
			loop_cnt = DDR_CA_CFG_CHECK_CNT;
			do{
				if(ddrc_chg_caeps->reg.oneop_chg_ca_ok){
					break;
				}
				loop_cnt--;
			}while (loop_cnt > 0);
			if(0 >= loop_cnt){
				tloge("fail to change ddr ca encrypt, ddrc_num = %d, dmc_num = %d \n", i, j);
				ret = ERROR;
				goto error_proc;
			}
		}
	}

	if(DIS_CA_RD == ca_rd_enable){
		g_ca_rd_cfg_flag = 0;
		tlogi("ca_rd_en = %d, disable ok \n", ddrc_cfg_ca->reg.ca_rd_en);
	}

error_proc:
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif

	if (OK != pthread_mutex_unlock(&g_ca_rd_pthread_lock)) {
			ret = ERROR;
			tloge("cfg:Release lock_flag failed!\n");
	}
	return ret;
}
#endif

static void cpu_addr_shift(u64 *phys)
{
	u64 phys_addr_start = *phys;
	u32 addr_shift_mode = (readl((uintptr_t)SOC_DMSS_ASI_ADDR_SHIFT_ADDR(SOC_ACPU_DMSS_BASE_ADDR, CPU_ASI_NUM))) & ADDR_SHIFT_MODE_MASK;
	tlogi("[%s]addr_shift_mode is %d \n", __func__, addr_shift_mode);

	if((addr_shift_mode == ADDR_SHIFT_MODE_1) && (phys_addr_start >= ADDR_SHIFT_MODE_1_START_ADDR) \
		&& (phys_addr_start < ADDR_SHIFT_MODE_1_END_ADDR))
	{
		*phys = phys_addr_start - ADDR_SHIFT_MODE_1_START_ADDR + DDR_SIZE_3G512M;
	}
	else if((addr_shift_mode == ADDR_SHIFT_MODE_2) && (phys_addr_start >= ADDR_SHIFT_MODE_2_START_ADDR) \
		&& (phys_addr_start < ADDR_SHIFT_MODE_2_END_ADDR))
	{
		*phys = phys_addr_start - ADDR_SHIFT_MODE_2_START_ADDR + DDR_SIZE_3G512M;
	}

	return;
}

static s32 tzmp2_cfg(u64 phys, u32 size, enum MPU_CFG_TYPE mpu_cfg_type)
{
	s32 ret = OK;
	u32 start_reg, bit_length_total, bit_length_reg, reg_value, reg_start_bit, loop_flag;

	if (OK != pthread_mutex_lock(&g_tzmp2_pthread_lock)) {
		tloge("check:Wait lock_flag failed!\n");
		return ERROR;
	}

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif

#if defined (CONFIG_HISI_DDR_CA_RD)
	if((mpu_cfg_type == MPU_SET_SEC) && (0 == g_ca_rd_cfg_flag)){
		if(OK != ddrc_ca_rd_cfg(EN_CA_RD)){
			tloge("ddrc_ca_cfg ca_enable fail \n");
			ret = ERROR;
			goto error_proc;
		}
		g_ca_rd_cfg_flag = 1;
	}
#endif

	if(size % g_mpu_seccfg_granularity_size != 0){
		tloge("size is not alignment with g_mpu_seccfg_granularity_size");
		ret = ERROR;
		goto error_proc;
	}

	cpu_addr_shift(&phys);
	tlogi("[%s]phys is 0x%llx, size is 0x%lx \n", __func__, phys, size);

	if((phys >= g_mpu_seccfg_addr_zone) || (0 == size) || ((phys + (u64)size) >= g_mpu_seccfg_addr_zone)){
		tloge("phys addr beyond g_mpu_seccfg_addr_zone or size equal 0\n");
		ret = ERROR;
		goto error_proc;
	}

	/*configure mpu ram, 1bit represent 64K/128K/256K*/
	start_reg = (phys / g_mpu_seccfg_granularity_size) / REG_BIT_NUM;
	reg_start_bit = (phys / g_mpu_seccfg_granularity_size) % REG_BIT_NUM;
	bit_length_total = size / g_mpu_seccfg_granularity_size;
	tlogi("s_r %d, r_s_b %d, b_l_t %d\n", start_reg, reg_start_bit, bit_length_total);

	do {
		loop_flag = 0;
		if ((reg_start_bit + bit_length_total) > REG_BIT_NUM){
			bit_length_reg = REG_BIT_NUM - reg_start_bit;
			loop_flag = 1;
		}else{
			bit_length_reg = bit_length_total;
		}

		reg_value = readl((uintptr_t)SOC_DMSS_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_TZMP2_BASE_ADDR, start_reg));
		if(mpu_cfg_type == MPU_SET_SEC){
			reg_value |= VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length_reg), reg_start_bit);
			writel(reg_value, (uintptr_t)SOC_DMSS_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_TZMP2_BASE_ADDR, start_reg));
			tlogi("[MPU_SET_SEC]start_reg %d, reg_start_bit %d, bit_length_total %d\n", start_reg, reg_start_bit, bit_length_total);
			tlogi("[MPU_SET_SEC]reg_value 0x%x, mpu_addr 0x%x\n", reg_value, SOC_DMSS_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_TZMP2_BASE_ADDR, start_reg));
		}
		else if(mpu_cfg_type == MPU_UNSET_SEC){
			reg_value &= ~(VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length_reg), reg_start_bit));
			writel(reg_value, (uintptr_t)SOC_DMSS_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_TZMP2_BASE_ADDR, start_reg));
			tlogi("[MPU_UNSET_SEC]start_reg %d, reg_start_bit %d, bit_length_total %d\n", start_reg, reg_start_bit, bit_length_total);
			tlogi("[MPU_UNSET_SEC]reg_value 0x%x, mpu_addr 0x%x\n", reg_value, SOC_DMSS_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_TZMP2_BASE_ADDR, start_reg));
		}
		else if(mpu_cfg_type == MPU_CHECK_SEC){
			reg_value &= VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length_reg), reg_start_bit);
			if(reg_value != VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length_reg), reg_start_bit)) {
				tlogi("[MPU_CHECK_SEC]reg_value 0x%x, bit_length_reg 0x%x, reg_start_bit 0x%x\n", reg_value, bit_length_reg, reg_start_bit);
				ret = ERROR;
				goto error_proc;
			}
		}
		else{
			tloge("wrong mpu_cfg_type\n");
			ret = ERROR;
			goto error_proc;
		}

		if(loop_flag){
			start_reg++;
			reg_start_bit = 0;
			bit_length_total -= bit_length_reg;
		}
	} while (loop_flag);

error_proc:
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif

	if (OK != pthread_mutex_unlock(&g_tzmp2_pthread_lock)) {
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

s32 tzmp2_init(void)
{
	u32 glb_mpu_cfg;

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	glb_mpu_cfg = readl(SOC_DMSS_GLB_MPU_CFG_ADDR);

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_CLIENT_SECURE_OS, DDR_AUTOFSGT_LOGIC_EN);
#endif

	switch(GET_MPU_ADDR_ZONE(glb_mpu_cfg)){
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
		default :
			tloge("tzmp2_init get mpu_addr_zone fail \n");
			return ERROR;
	}

	return OK;
}
