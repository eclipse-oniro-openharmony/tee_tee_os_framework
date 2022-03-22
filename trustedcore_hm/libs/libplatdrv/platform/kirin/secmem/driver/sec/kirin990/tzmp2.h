/*************************************************************
*文  件  名  字:	tzmp2.h
*
*文  件  描  述:	tzmp2.h
*
*作  者  名  字:	x00431728
*
*生  成  时  间:	2018-09-7
*************************************************************/


#ifndef __TZMP2_H__
#define __TZMP2_H__

/**********************************************************
 头文件
**********************************************************/
#include "soc_acpu_baseaddr_interface.h"

/**********************************************************
 宏
**********************************************************/
#define SOC_DMSS_ASI_ADDR_SHIFT_ADDR(base, asi_base)  ((base) + (0x020+0x800*(asi_base)))
#define SOC_ACPU_DMSS_TZMP2_BASE_ADDR (SOC_ACPU_DMSS_BASE_ADDR + 0x20000)
#define SOC_DMSS_GLB_MPU_CFG_ADDR     (SOC_ACPU_DMSS_BASE_ADDR + 0x16380)
#define GET_MPU_ADDR_ZONE(val)        ((val & 0x30) >> 4)
#define MPU_ADDR_ZONE_4G  (0)
#define MPU_ADDR_ZONE_8G  (1)
#define MPU_ADDR_ZONE_16G (2)
#define ADDR_SHIFT_MODE_MASK (3)
#define ADDR_SHIFT_MODE_1    (1)
#define ADDR_SHIFT_MODE_2    (2)
#define DDR_SIZE_64K  (0x10000)
#define DDR_SIZE_128K (0x20000)
#define DDR_SIZE_256K (0x40000)
#define DDR_SIZE_3G512M      (0xE0000000ULL)
#define DDR_SIZE_4G          (0x100000000ULL)
#define DDR_SIZE_8G          (0x200000000ULL)
#define DDR_SIZE_8G512M      (0x220000000ULL)
#define DDR_SIZE_16G         (0x400000000ULL)
#define DDR_SIZE_16G512M     (0x420000000ULL)
#define DDR_SIZE_32G         (0x800000000ULL)
#define DDR_SIZE_32G512M     (0x820000000ULL)
#define ADDR_SHIFT_MODE_1_START_ADDR    DDR_SIZE_16G
#define ADDR_SHIFT_MODE_1_END_ADDR      DDR_SIZE_16G512M
#define ADDR_SHIFT_MODE_2_START_ADDR    DDR_SIZE_32G
#define ADDR_SHIFT_MODE_2_END_ADDR      DDR_SIZE_32G512M

#define CPU_ASI_NUM (6)

#define REG_BIT_NUM  (32)
#define OK    (0)
#define ERROR (-1)
#define PRINT_INFO tlogi
#define writel(val, addr)	(((*(volatile u32 *)addr)) = (val))
#define readl(addr)			(*(volatile u32 *)addr)
#define SOC_DMSS_MPU_ADDR_ATTR_ADDR(base, mpu_regs)  ((base) + (0x4*(mpu_regs)))
#define BITS_WIDTH_MASK(num)		((u32)((1ULL << (num)) - 1))
#define VALUE_SHIFT_WIDTH(value, width_bit)   ((u32)((value) << (width_bit)))
#define SOC_DDRC_DMC_DDRC_CFG_CA_ADDR(base)    ((base) + (0x180))
#define SOC_DDRC_DMC_DDRC_CHG_CAEPS_ADDR(base) ((base) + (0x1Bc))
#define SOC_ACPU_DMCPACK0_BASE_ADDR            (0xFFE00000)

#define CA_RD_ENABLE (0xA)
#define CA_WR_ENABLE (0xA)
#define CA_RD_DISABLE (0x5)
#define CA_WR_DISABLE (0x5)
#define DDR_CA_CFG_CHECK_CNT (1000)
#define BIT(x)    (1 << (x))

typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  ca_wr_en     : 4;  /* bit[0-3] : 写命令是否bypass加解密通路。只能安全访问可以写。
                                                       'b0101：bypass掉加解密通路
                                                       'bXXX0：开启加解密功能。
                                                       Others：送出全0或全1值。 */
        unsigned int  ca_rd_en     : 4;  /* bit[4-7] : 读命令是否bypass加解密通路。只能安全访问可以写。
                                                       'b0101：bypass掉加解密通路
                                                       'bXXX0：开启加解密功能。
                                                       Others：送出全0或全1值。 */
        unsigned int  rst_int_mask : 1;  /* bit[8]   : 复位中断的mask标记。只有安全访问可以写。
                                                       0：使能中断；
                                                       1：屏蔽中断。 */
        unsigned int  reserved     : 23; /* bit[9-31]: 保留。 */
    } reg;
} SOC_DDRC_DMC_DDRC_CFG_CA_UNION;

typedef union
{
    unsigned int      value;
    struct
    {
        unsigned int  oneop_chg_caeps  : 1;  /* bit[0]    : 是否使用硬件一键改写解密使能的功能，使用的话，不需要软件参与反压主通路，软件直接改写解密使能即可；不使用的话，需要软件先将主通路反压，然后再改写解密使能。
                                                            1'b0: 不使用
                                                            1'b1: 使用 */
        unsigned int  reserved_0       : 7;  /* bit[1-7]  : 保留。 */
        unsigned int  oneop_chg_ca_ok  : 1;  /* bit[8]    : 改写ca解密使能成功。 */
        unsigned int  oneop_chg_eps_ok : 1;  /* bit[9]    : 改写eps解密使能成功。 */
        unsigned int  reserved_1       : 22; /* bit[10-31]: 保留。 */
    } reg;
} SOC_DDRC_DMC_DDRC_CHG_CAEPS_UNION;

/**********************************************************
 枚举
**********************************************************/
enum MPU_CFG_TYPE
{
	MPU_SET_SEC,
	MPU_UNSET_SEC,
	MPU_CHECK_SEC,
};

#endif
