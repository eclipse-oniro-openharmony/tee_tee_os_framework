/*************************************************************
*文 件 名 字:	hisi_ddr_sec_region_kirin970.h
*
*文 件 描 述:	hisi_ddr_sec_region_kirin970.h
*
*作 者 名 字:	刘聪 l00353600
*
*生 成 时 间:	2017-9-11
*************************************************************/

/*************************************************************
  头文件
*************************************************************/

/*************************************************************
  宏定义
*************************************************************/

/*should be the same as bl31*/
#define SEC_RGN_RESRVED_NUM 	(11)
#define SEC_RGN_TOP_CORESIGHT_RESERVED (11)
#define SEC_RGN_XMODE_DUMP_RESERVED (10)	/*ASI subsys*/
#define SEC_RGN_KERNEL_READ_ONLY_RESERVED (10)	/*ASI CPU*/
#define SEC_RGN_KERNEL_PROTECT_RESERVED (SEC_RGN_KERNEL_READ_ONLY_RESERVED)	/*disable，需要保证KERNEL_READ_ONLY不会check其他已用region*/
#define SEC_RGN_IDENTIFICATION_RESERVED (9)
#define SEC_RGN_HIFI_REBOOT_RESERVED (8)
#define SEC_RGN_ION_RESERVED (7)    /*rgn起始位置 倒数*/
#define SEC_RGN_ION_RESERVED_NUM (7) /*rgn预留个数*/
#define SEC_RGN_XMODE_DUMP_RESERVED_ASI0 (1)

#define REG_BASE_DMSS	(0xFFFC0000)
#define ASI_NUM_MAX	(11)
#define CPU_ASI_NUM (6)
#define ADDR_SHIFT_MODE_1_START_ADDR    DDR_SIZE_4G
#define ADDR_SHIFT_MODE_1_END_ADDR      DDR_SIZE_4G512M
#define ADDR_SHIFT_MODE_2_START_ADDR    DDR_SIZE_8G
#define ADDR_SHIFT_MODE_2_END_ADDR      DDR_SIZE_8G512M

/*kirin970 sec rgn granularity is 64K (addr low 16bit should be 0)*/
#define SEC_RGN_ADDR_SHIFT (16)
#define SEC_RGN_ADDR_MASK (0xFFFFULL)

#define ALL_ASI_MASK (0x7FF)

/*sec region mid width mask*/
#define SEC_ASI0_MASK      (0x1F)
#define SEC_ASI12_MASK       (0xF)
#define SEC_ASI34_MASK       (0x1F)
#define SEC_ASI5_MASK       (0x3)
#define SEC_ASI679A_MASK       (0x7)
#define SEC_ASI8_MASK       (0x1F)

#define MODEM_CCPU_ASI_MASK		(0x1)
#define VDEC_ASI_MASK		((1<<1)|(1<<2))
#define ISP_DSS_ASI_MASK	((1<<3)|(1<<4))
#define IVP32_ASI_MASK		(1<<5)
#define CPU_GPU_ASI_MASK 	((1<<6)|(1<<7)|(1<<9)|(1<<10))
#define SUBSYS_ASI_MASK 	(1<<8)
#define DDR_SEC_ALL_ASI_MASK	(MODEM_CCPU_ASI_MASK | VDEC_ASI_MASK |\
	ISP_DSS_ASI_MASK | IVP32_ASI_MASK | CPU_GPU_ASI_MASK | SUBSYS_ASI_MASK)

/*KIRIN970 CS MID bit[0-4]*/
/*ASI 8*/
#define SOC_DJTAG_M_MID		(0x05)
#define SOC_SEC_S_MID		(0x0A)
#define SOC_TOP_CSSYS_MID	(0x0F)
#define SOC_DMAC_MID		(0x10)
#define DJTAG_M_MID		(SOC_DJTAG_M_MID & SEC_ASI8_MASK)
#define SEC_S_MID		(SOC_SEC_S_MID & SEC_ASI8_MASK)
#define TOP_CSSYS_MID	(SOC_TOP_CSSYS_MID & SEC_ASI8_MASK)
#define DMAC_MID		(SOC_DMAC_MID & SEC_ASI8_MASK)

/*ASI 6/7/9/10*/
#define SOC_CPU_ARTEMIS_MID            (0x78)
#define SOC_CPU_A53_MID             (0x79)

#define CPU_ARTEMIS_MID	(SOC_CPU_ARTEMIS_MID & SEC_ASI679A_MASK)
#define CPU_A53_MID			(SOC_CPU_A53_MID & SEC_ASI679A_MASK)
#define CPU_ALL	((1 << CPU_ARTEMIS_MID) | (1 << CPU_A53_MID))

#define FORBID_MID	(0x0)
#define ALL_MID	(0xFFFFFFFF)
/*************************************************************
  枚举类型
*************************************************************/

/*************************************************************
  结构体
*************************************************************/

/*************************************************************
  函数声明
*************************************************************/


