#include "drv_module.h"
#include "drv_mem.h"  // sre_mmap
#include "sre_log.h"
#include "mem_ops.h"
#include "mem_page_ops.h"
#include <tzmp2_ops.h>
#include "sec_region.h"
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
#include "hisi_ddr_autofsgt_proxy_secure_os.h"
#endif

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260) || \
	(TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW)
#define SOC_ACPU_DMSS_TZMP2_BASE_ADDR (0xFFFB0000)
#else
#define SOC_ACPU_DMSS_TZMP2_BASE_ADDR (0xEA980000 + 0x20000)
#endif

#define SZ_64k 0x10000
#define writel(val, addr)	(((*(volatile u32 *)addr)) = (val))
#define readl(addr)			(*(volatile u32 *)addr)
#define SOC_DMSS_MPU_MPU_ADDR_ATTR_ADDR(base, mpu_regs)  ((base) + (0x4*(mpu_regs)))
#define BITS_WIDTH_MASK(num)                  ((u32)(((1UL << (num)) - 1)))
#define VALUE_SHIFT_WIDTH(value, width_bit)   ((u32)((value) << (width_bit)))


static void cpu_addr_shift(u64 *phys)
{
	u64 phys_addr_start = *phys;

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	u32 addr_shift_mode = (readl(SOC_DMSS_ASI_ADDR_SHIFT_ADDR(REG_BASE_DMSS, CPU_ASI_NUM))) & ADDR_SHIFT_MODE_MASK;
	tlogi("[%s]addr_shift_mode is %d \n", __func__, addr_shift_mode);

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif

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
int tzmp2_set_sec(u64 phys, u32 size)
{
	u32 start_bit, end_bit, start_reg, bit_length, reg_value, tmp;

	if(size % (1 << 16) != 0)
		return -1;

	cpu_addr_shift(&phys);
	tlogi("[%s]phys is 0x%llx \n", __func__, phys);

	if((phys >= DDR_SIZE_4G) || (0 == size) || ((phys + (u64)size) >= DDR_SIZE_4G)){
		tloge("[%s]phys addr beyond 4G or size equals 0 \n", __func__);
		return -1;
	}

	/*configure mpu ram*/
	start_bit = phys >> 16;
	bit_length = size >> 16;
	end_bit = start_bit + bit_length;
	start_reg = start_bit / 32;

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	tmp = start_bit % 32;
	if (bit_length + tmp > 32)
		bit_length = 32 - tmp;
	do {
		reg_value = readl((uintptr_t)SOC_DMSS_MPU_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_TZMP2_BASE_ADDR, start_reg)); //lint !e720
		reg_value |= VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length), tmp);

		writel(reg_value, (uintptr_t)SOC_DMSS_MPU_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_TZMP2_BASE_ADDR, start_reg)); //lint !e720
		start_reg++;
		start_bit += bit_length;
		tmp = 0;
		bit_length = ((end_bit - start_bit) >= 32) ? 32 : (end_bit - start_bit);
	} while ((start_bit < end_bit) && (bit_length > 0));

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif

	return 0;
}


int tzmp2_unset_sec(u64 phys, u32 size)
{
	u32 start_bit, end_bit, start_reg, bit_length, reg_value, tmp;

	if(size % (1 << 16) != 0)
		return -1;

	cpu_addr_shift(&phys);

	if((phys >= DDR_SIZE_4G) || (0 == size) || ((phys + (u64)size) >= DDR_SIZE_4G)){
		tloge("[%s]phys addr beyond 4G or size equals 0 \n", __func__);
		return -1;
	}
	/*clear mpu ram*/
	start_bit = phys >> 16;
	bit_length = size >> 16;
	end_bit = start_bit + bit_length;

	start_reg = start_bit / 32;
	tmp = start_bit % 32;
	if (bit_length + tmp > 32)
		bit_length = 32 - tmp;

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	do {
		reg_value = readl((uintptr_t)SOC_DMSS_MPU_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_TZMP2_BASE_ADDR, start_reg)); //lint !e720
		reg_value &= ~(VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length), tmp));

		writel(reg_value, (uintptr_t)SOC_DMSS_MPU_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_TZMP2_BASE_ADDR, start_reg)); //lint !e720
		start_reg++;
		start_bit += bit_length;
		tmp = 0;
		bit_length = ((end_bit - start_bit) >= 32) ? 32 : (end_bit - start_bit);
	} while ((start_bit < end_bit) && (bit_length > 0));

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif

	return 0;
}

s32 tzmp2_check_sec(u64 phys, u32 size)
{
	u32 start_bit, end_bit, start_reg, bit_length, reg_value, tmp;

	cpu_addr_shift(&phys);

	if((phys >= DDR_SIZE_4G) || (0 == size) || ((phys + (u64)size) >= DDR_SIZE_4G)){
		tloge("[%s]phys addr beyond 4G or size equals 0 \n", __func__);
		return -1;
	}
	start_bit = phys >> 16;
	bit_length = (size  + ((1 << 16) - 1)) >> 16;
	end_bit = start_bit + bit_length;

	start_reg = start_bit / 32;
	tmp = start_bit % 32;
	if (bit_length + tmp > 32)
		bit_length = 32 - tmp;

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_DIS);
#endif

	do {
		reg_value = readl((uintptr_t)SOC_DMSS_MPU_MPU_ADDR_ATTR_ADDR(SOC_ACPU_DMSS_TZMP2_BASE_ADDR, start_reg)); //lint !e720
		reg_value &= VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length), tmp);

		if(reg_value != VALUE_SHIFT_WIDTH(BITS_WIDTH_MASK(bit_length), tmp)) {
#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif
			return -1;
		}
		start_reg++;
		start_bit += bit_length;
		tmp = 0;
		bit_length = ((end_bit - start_bit) >= 32) ? 32 : (end_bit - start_bit);
	} while ((start_bit < end_bit) && (bit_length > 0));

#if defined(CONFIG_HISI_DDR_AUTO_FSGT)
	(void)ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_SETSEC, DDR_AUTOFSGT_LOGIC_EN);
#endif

	return 0;
}

s32 tzmp2_init(void)
{
	return 0;
}

