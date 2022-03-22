/*************************************************************
*文  件  名  字:	sec_region.h
*
*文  件  描  述:	sec_region.h
*
*作  者  名  字:	w00294303
*
*生  成  时  间:	2017-03-08
*************************************************************/


#ifndef __SEC_REGION_H__
#define __SEC_REGION_H__

/**********************************************************
 头文件
**********************************************************/

#include "hisi_ddr_sec_region_plat.h"
#include <global_ddr_map.h>

/**********************************************************
 宏
**********************************************************/
typedef unsigned long long u64;
typedef unsigned int u32;

#define BIT(n)				        (1U << (n))
#define OK    (0)
#define ERROR (-1)
#define ERROR_ADDR (-2)

#ifdef DEF_ENG
#define PRINT_DEBUG tloge
#else
#define PRINT_DEBUG tlogi
#endif
#define PRINT_ERROR tloge
#define PRINT_INFO tlogi

#define UNSEC_ADDR  (0)
#define SEC_ADDR    (1)

#define TOP_CORESIGHT_PHYMEM_SIZE (0x20000)
#define TOP_CORESIGHT_PHYMEM_BASE (HISI_RESERVED_SECOS_PHYMEM_BASE+HISI_RESERVED_SECOS_PHYMEM_SIZE-TOP_CORESIGHT_PHYMEM_SIZE)
#define TOP_CORESIGHT_PHYMEM_END (TOP_CORESIGHT_PHYMEM_BASE + TOP_CORESIGHT_PHYMEM_SIZE)
#define KERNEL_END_ADDR           HISI_RESERVED_KERNEL_CAN_RUN_END

#define SOC_DMSS_ASI_RTL_INF2_ADDR(base, asi_base)    ((base) + (0x008+0x800*(asi_base)))
#define SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(base, sec_rgns, asi_base)  ((base) + (0x500+0x10*(sec_rgns)+0x800*(asi_base)))
#define SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(base, sec_rgns, asi_base)  ((base) + (0x504+0x10*(sec_rgns)+0x800*(asi_base)))
#define SOC_DMSS_ASI_SEC_MID_WR_ADDR(base, sec_rgns, asi_base)  ((base) + (0x508+0x10*(sec_rgns)+0x800*(asi_base)))
#define SOC_DMSS_ASI_SEC_MID_RD_ADDR(base, sec_rgns, asi_base)  ((base) + (0x50C+0x10*(sec_rgns)+0x800*(asi_base)))
#define SOC_DMSS_ASI_ADDR_SHIFT_ADDR(base, asi_base)  ((base) + (0x020+0x800*(asi_base)))
#define ADDR_SHIFT_MODE_MASK (3)
#define ADDR_SHIFT_MODE_1    (1)
#define ADDR_SHIFT_MODE_2    (2)
#define DDR_SIZE_3G512M      (0xE0000000ULL)
#define DDR_SIZE_4G          (0x100000000ULL)
#define DDR_SIZE_4G512M      (0x120000000ULL)
#define DDR_SIZE_8G          (0x200000000ULL)
#define DDR_SIZE_8G512M      (0x220000000ULL)
#define DDR_SIZE_15G512M     (0x3E0000000ULL)
#define DDR_SIZE_16G         (0x400000000ULL)

#define MDDRC_MAX_RGN	(32)
#define INVALID_REGION_INDEX		0x5e5e5e5e /*invalid index definition of region.*/

/**********************************************************
 结构体
**********************************************************/
/**********************************************************
寄存器结构体
**********************************************************/
typedef union
{
	unsigned int      value;
	struct
	{
		unsigned int  rgn_base_addr : 20;
		unsigned int  reserved      : 11;
		unsigned int  rgn_en        : 1;
	} reg;
} SOC_DMSS_ASI_SEC_RGN_MAP0_UNION;
#define SOC_DMSS_ASI_SEC_RGN_MAP0_rgn_base_addr_START  (0)
#define SOC_DMSS_ASI_SEC_RGN_MAP0_rgn_base_addr_END    (19)
#define SOC_DMSS_ASI_SEC_RGN_MAP0_rgn_en_START         (31)
#define SOC_DMSS_ASI_SEC_RGN_MAP0_rgn_en_END           (31)

typedef union
{
	unsigned int      value;
	struct
	{
		unsigned int  rgn_top_addr : 20;
		unsigned int  reserved     : 8;
		unsigned int  sp           : 4;
	} reg;
} SOC_DMSS_ASI_SEC_RGN_MAP1_UNION;
#define SOC_DMSS_ASI_SEC_RGN_MAP1_rgn_top_addr_START  (0)
#define SOC_DMSS_ASI_SEC_RGN_MAP1_rgn_top_addr_END    (19)
#define SOC_DMSS_ASI_SEC_RGN_MAP1_sp_START            (28)
#define SOC_DMSS_ASI_SEC_RGN_MAP1_sp_END              (31)

typedef union
{
	unsigned int      value;
	struct
	{
		unsigned int  mid_sel_wr : 32;
	} reg;
} SOC_DMSS_ASI_SEC_MID_WR_UNION;
#define SOC_DMSS_ASI_SEC_MID_WR_mid_sel_wr_START  (0)
#define SOC_DMSS_ASI_SEC_MID_WR_mid_sel_wr_END    (31)

typedef union
{
	unsigned int      value;
	struct
	{
		unsigned int  mid_sel_rd : 32;
	} reg;
} SOC_DMSS_ASI_SEC_MID_RD_UNION;
#define SOC_DMSS_ASI_SEC_MID_RD_mid_sel_rd_START  (0)
#define SOC_DMSS_ASI_SEC_MID_RD_mid_sel_rd_END    (31)

/*************************************************/

enum {
	RW_FORBID = 0,        /* can't read or write in sec and un_sec*/
	UNSEC_WR = 0x1,    /* unsec write */
	UNSEC_RD = 0x2,     /* unsec read */
	SEC_WR = 0x4,      /* sec write */
	SEC_RD = 0x8,       /* sec read */
};

/*one region*/
typedef struct {
	unsigned int rgn_en:1;
	unsigned int attri:4;
	unsigned long long start_addr;
	unsigned long long end_addr;
	unsigned int mid_wr;
	unsigned int mid_rd;
} SEC_RGN_CFG;

/**********************************************************
 函数接口
**********************************************************/

#endif
