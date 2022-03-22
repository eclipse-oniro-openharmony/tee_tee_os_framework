/*************************************************************
*文  件  名  字:	sec_region.h
*
*文  件  描  述:	sec_region.h
*
*作  者  名  字:	x00431728
*
*生  成  时  间:	2018-08-1
*************************************************************/


#ifndef __SEC_REGION_H__
#define __SEC_REGION_H__

/**********************************************************
 头文件
**********************************************************/
#include "soc_acpu_baseaddr_interface.h"
#include "soc_mid.h"
#include <global_ddr_map.h>

/**********************************************************
 宏
**********************************************************/
typedef unsigned long long u64;
typedef unsigned int u32;

/*should be the same as bl31*/
#define SEC_RGN_RESRVED_NUM 	(10)
#define SEC_RGN_KERNEL_READ_ONLY_RESERVED (10)	/*ASI CPU*/
#define SEC_RGN_XMODE_DUMP_RESERVED (10)		/*ASI subsys*/
#define SEC_RGN_IDENTIFICATION_RESERVED (9)
#define SEC_RGN_KERNEL_PROTECT_RESERVED (8)
#define SEC_RGN_HIFI_REBOOT_RESERVED (7)
#define SEC_RGN_TUI_RESERVED (6)		/*tui_rgn起始位置 倒数*/
#define SEC_RGN_TUI_RESERVED_NUM (3)	/*tui_rgn预留个数*/
#define SEC_RGN_SION_RESERVED (3)	/*sion_rgn起始位置 倒数*/
#define SEC_RGN_SION_RESERVED_NUM (3) /*sion_rgn预留个数*/

#define KERNEL_END_ADDR   HISI_RESERVED_KERNEL_CAN_RUN_END

#define REG_BASE_DMSS	SOC_ACPU_DMSS_BASE_ADDR
#define ASI_NUM_MAX	(10)

#define UNSEC_ADDR  (0)
#define SEC_ADDR    (1)

/*kirin990 sec rgn granularity is 64K (addr low 16bit should be 0)*/
#define SEC_RGN_ADDR_SHIFT (16)
#define SEC_RGN_ADDR_MASK (0xFFFFULL)

#define ALL_ASI_MASK (0x3FF)

#define MODEM_CCPU_ASI_MASK	(0x1)
#define NPU_ASI_MASK 		(1<<1)
#define VDEC_IVP_ASI_MASK	(1<<2)
#define ISP_DSS_ASI_MASK	(1<<3)
#define CPU_ASI_MASK 		(1<<5)
#define SUBSYS_ASI_MASK 	(1<<7)
#define GPU_ASI_MASK 		(1<<8)

#define DDR_SEC_ALL_ASI_MASK	(MODEM_CCPU_ASI_MASK | VDEC_IVP_ASI_MASK |\
	ISP_DSS_ASI_MASK | SUBSYS_ASI_MASK | CPU_ASI_MASK | NPU_ASI_MASK | GPU_ASI_MASK)

#define CPU_ASI_NUM	(5)

/*MID bit[0-4]*/
/*ASI 7*/
#define LPMCU_MID		(SOC_LPMCU_MID & SEC_ASI7_MASK)
#define IOMCU_HS47D_MID	(SOC_IOMCU_HS47D_MID & SEC_ASI7_MASK)
#define PERF_STAT_MID	(SOC_PERF_STAT_MID & SEC_ASI7_MASK)
#define IPF_MID			(SOC_IPF_MID & SEC_ASI7_MASK)
#define DJTAG_M_MID	(SOC_DJTAG_M_MID & SEC_ASI7_MASK)
#define IOMCU_DMA_MID	(SOC_IOMCU_DMA_MID & SEC_ASI7_MASK)
#define UFS_MID			(SOC_UFS_MID & SEC_ASI7_MASK)
#define SD_MID			(SOC_SD_MID & SEC_ASI7_MASK)
#define SDIO_MID		(SOC_SDIO_MID & SEC_ASI7_MASK)
#define CC712_MID		(SOC_CC712_MID & SEC_ASI7_MASK)
#define SOCP_MID		(SOC_SOCP_MID & SEC_ASI7_MASK)
#define USB200TG_MID	(SOC_USB200TG_MID & SEC_ASI7_MASK)
#define TOP_CSSYS_MID	(SOC_TOP_CSSYS_MID & SEC_ASI7_MASK)
#define DMAC_MID		(SOC_DMAC_MID & SEC_ASI7_MASK)
#define ASP_HIFI_MID	(SOC_ASP_HIFI_MID & SEC_ASI7_MASK)
#define ASP_DMA_MID		(SOC_ASP_DMA_MID & SEC_ASI7_MASK)
#define EMMC_MID		(SOC_EMMC_MID & SEC_ASI7_MASK)
#define ATGS_MID		(SOC_ATGS_MID & SEC_ASI7_MASK)

#define MODEM_DFC_MID_ASI7			(SOC_MODEM_DFC_MID & SEC_ASI7_MASK)
#define MODEM_CIPHER_MID_ASI7		(SOC_MODEM_CIPHER_MID & SEC_ASI7_MASK)
#define MODEM_HDLC_MID_ASI7		(SOC_MODEM_HDLC_MID & SEC_ASI7_MASK)
#define MODEM_CICOM0_MID_ASI7		(SOC_MODEM_CICOM0_MID & SEC_ASI7_MASK)
#define MODEM_CICOM1_MID_ASI7		(SOC_MODEM_CICOM1_MID & SEC_ASI7_MASK)
#define MODEM_TL_BBP_DMA_TCM_MID_ASI7	(SOC_MODEM_TL_BBP_DMA_TCM_MID & SEC_ASI7_MASK)
#define MODEM_TL_BBP_DMA_DDR_MID_ASI7	(SOC_MODEM_TL_BBP_DMA_DDR_MID & SEC_ASI7_MASK)
#define MODEM_GU_BBP_MST_TCM_MID_ASI7	(SOC_MODEM_GU_BBP_MST_TCM_MID & SEC_ASI7_MASK)
#define MODEM_GU_BBP_MST_DDR_MID_ASI7	(SOC_MODEM_GU_BBP_MST_DDR_MID & SEC_ASI7_MASK)
#define MODEM_EDMA0_MID_ASI7		(SOC_MODEM_EDMA0_MID & SEC_ASI7_MASK)
#define MODEM_EDMA1_MID_ASI7		(SOC_MODEM_EDMA1_MID & SEC_ASI7_MASK)
#define MODEM_HARQ_L_MID_ASI7		(SOC_MODEM_HARQ_L_MID & SEC_ASI7_MASK)
#define MODEM_HARQ_H_MID_ASI7		(SOC_MODEM_HARQ_H_MID & SEC_ASI7_MASK)
#define MODEM_UPACC_MID_ASI7		(SOC_MODEM_UPACC_MID & SEC_ASI7_MASK)
#define MODEM_RSR_ACC_MID_ASI7		(SOC_MODEM_RSR_ACC_MID & SEC_ASI7_MASK)
#define MODEM_CIPHER_WRITE_THOUGH_MID_ASI7	(SOC_MODEM_CIPHER_WRITE_THOUGH_MID & SEC_ASI7_MASK)
#define MODEM_CCPU_CFG_MID	(SOC_MODEM_CCPU_CFG_MID & SEC_ASI7_MASK)
#define MODEM_SUBSYS_ASI7	((1 << MODEM_CIPHER_MID_ASI7) | (1 << MODEM_CICOM0_MID_ASI7) | (1 << MODEM_CICOM1_MID_ASI7) \
	 | (1 << MODEM_TL_BBP_DMA_TCM_MID_ASI7) | (1 << MODEM_TL_BBP_DMA_DDR_MID_ASI7) | (1 << MODEM_GU_BBP_MST_TCM_MID_ASI7) \
	| (1 << MODEM_GU_BBP_MST_DDR_MID_ASI7) | (1 << MODEM_EDMA0_MID_ASI7) | (1 << MODEM_EDMA1_MID_ASI7) | (1 << MODEM_HARQ_L_MID_ASI7) \
	| (1 << MODEM_HARQ_H_MID_ASI7) | (1 << MODEM_UPACC_MID_ASI7) | (1 << MODEM_RSR_ACC_MID_ASI7))   /*no IPF/DFC/CIPHER_WRITE_THOUGH/SOCP/CCPU_CFG/NXDSP*/

/*ASI 0*/
#define MODEM_NXDSP_MID			(SOC_MODEM_NXDSP_MID & SEC_ASI0_MASK)
#define MODEM_HARQ_L_MID_ASI0	(SOC_MODEM_HARQ_L_MID & SEC_ASI0_MASK)
#define MODEM_HARQ_H_MID_ASI0	(SOC_MODEM_HARQ_H_MID & SEC_ASI0_MASK)
#define MODEM_CCPU_L2C_MID		(SOC_MODEM_CCPU_L2C_MID & SEC_ASI0_MASK)
#define MODEM_DFC_MID_ASI0		(SOC_MODEM_DFC_MID & SEC_ASI0_MASK)
#define MODEM_CIPHER_MID_ASI0	(SOC_MODEM_CIPHER_MID & SEC_ASI0_MASK)
#define MODEM_HDLC_MID_ASI0		(SOC_MODEM_HDLC_MID & SEC_ASI0_MASK)
#define MODEM_CICOM0_MID_ASI0	(SOC_MODEM_CICOM0_MID & SEC_ASI0_MASK)
#define MODEM_CICOM1_MID_ASI0	(SOC_MODEM_CICOM1_MID & SEC_ASI0_MASK)
#define MODEM_TL_BBP_DMA_TCM_MID_ASI0	(SOC_MODEM_TL_BBP_DMA_TCM_MID & SEC_ASI0_MASK)
#define MODEM_TL_BBP_DMA_DDR_MID_ASI0	(SOC_MODEM_TL_BBP_DMA_DDR_MID & SEC_ASI0_MASK)
#define MODEM_GU_BBP_MST_TCM_MID_ASI0	(SOC_MODEM_GU_BBP_MST_TCM_MID & SEC_ASI0_MASK)
#define MODEM_GU_BBP_MST_DDR_MID_ASI0	(SOC_MODEM_GU_BBP_MST_DDR_MID & SEC_ASI0_MASK)
#define MODEM_EDMA0_MID_ASI0			(SOC_MODEM_EDMA0_MID & SEC_ASI0_MASK)
#define MODEM_EDMA1_MID_ASI0			(SOC_MODEM_EDMA1_MID & SEC_ASI0_MASK)
#define MODEM_UPACC_MID_ASI0			(SOC_MODEM_UPACC_MID & SEC_ASI0_MASK)
#define MODEM_RSR_ACC_MID_ASI0			(SOC_MODEM_RSR_ACC_MID & SEC_ASI0_MASK)
#define MODEM_CIPHER_WRITE_THOUGH_MID_ASI0	(SOC_MODEM_CIPHER_WRITE_THOUGH_MID & SEC_ASI0_MASK)
#define MODEM_SUBSYS_ASI0 	((1 << MODEM_CCPU_L2C_MID) | (1 << MODEM_NXDSP_MID) | (1 << MODEM_DFC_MID_ASI0) | (1 << MODEM_CIPHER_MID_ASI0)\
	| (1 << MODEM_HDLC_MID_ASI0) | (1 << MODEM_CICOM0_MID_ASI0) | (1 << MODEM_CICOM1_MID_ASI0) | (1 << MODEM_TL_BBP_DMA_TCM_MID_ASI0)\
	| (1 << MODEM_TL_BBP_DMA_DDR_MID_ASI0) | (1 << MODEM_GU_BBP_MST_TCM_MID_ASI0) | (1 << MODEM_GU_BBP_MST_DDR_MID_ASI0) | (1 << MODEM_EDMA0_MID_ASI0)\
	| (1 << MODEM_EDMA1_MID_ASI0) | (1 << MODEM_HARQ_L_MID_ASI0) | (1 << MODEM_HARQ_H_MID_ASI0) | (1 << MODEM_UPACC_MID_ASI0)\
	| (1 << MODEM_RSR_ACC_MID_ASI0))/*all of ASI0 except MODEM_CIPHER_WRITE_THOUGH_MID_ASI0*/

/*ASI 3/4*/
#define ISP_1_ISP_CORE_0_MID	(SOC_ISP_1_ISP_CORE_0_MID & SEC_ASI34_MASK)
#define ISP_1_ISP_CORE_1_MID	(SOC_ISP_1_ISP_CORE_1_MID & SEC_ASI34_MASK)
#define ISP_1_ISP_CORE_2_MID	(SOC_ISP_1_ISP_CORE_2_MID & SEC_ASI34_MASK)
#define ISP_1_ISP_CORE_3_MID	(SOC_ISP_1_ISP_CORE_3_MID & SEC_ASI34_MASK)
#define ISP_1_ISP_CORE_4_MID	(SOC_ISP_1_ISP_CORE_4_MID & SEC_ASI34_MASK)
#define ISP_1_ISP_CORE_5_MID	(SOC_ISP_1_ISP_CORE_5_MID & SEC_ASI34_MASK)
#define ISP_1_ISP_CORE_6_MID	(SOC_ISP_1_ISP_CORE_6_MID & SEC_ASI34_MASK)
#define ISP_1_ISP_CORE_7_MID	(SOC_ISP_1_ISP_CORE_7_MID & SEC_ASI34_MASK)
#define ISP_2_ISP_CORE_0_MID	(SOC_ISP_2_ISP_CORE_0_MID & SEC_ASI34_MASK)
#define ISP_2_ISP_CORE_1_MID	(SOC_ISP_2_ISP_CORE_1_MID & SEC_ASI34_MASK)
#define ISP_2_ISP_CORE_2_MID	(SOC_ISP_2_ISP_CORE_2_MID & SEC_ASI34_MASK)
#define ISP_2_ISP_CORE_3_MID	(SOC_ISP_2_ISP_CORE_3_MID & SEC_ASI34_MASK)
#define ISP_2_ISP_CORE_4_MID	(SOC_ISP_2_ISP_CORE_4_MID & SEC_ASI34_MASK)
#define ISP_2_ISP_CORE_5_MID	(SOC_ISP_2_ISP_CORE_5_MID & SEC_ASI34_MASK)
#define ISP_2_ISP_CORE_6_MID	(SOC_ISP_2_ISP_CORE_6_MID & SEC_ASI34_MASK)
#define ISP_2_ISP_JPEG_MID	(SOC_ISP_2_ISP_JPEG_MID & SEC_ASI34_MASK)
#define DSS_CMDLIST_MID	(SOC_DSS_CMDLIST_MID & SEC_ASI34_MASK)
#define DSS_WR_1_MID	(SOC_DSS_WR_1_MID & SEC_ASI34_MASK)
#define DSS_WR_0_MID	(SOC_DSS_WR_0_MID & SEC_ASI34_MASK)
#define DSS_RD_8_MID	(SOC_DSS_RD_8_MID & SEC_ASI34_MASK)
#define DSS_RD_7_MID	(SOC_DSS_RD_7_MID & SEC_ASI34_MASK)
#define DSS_RD_6_MID	(SOC_DSS_RD_6_MID & SEC_ASI34_MASK)
#define DSS_RD_5_MID	(SOC_DSS_RD_5_MID & SEC_ASI34_MASK)
#define DSS_RD_4_MID	(SOC_DSS_RD_4_MID & SEC_ASI34_MASK)
#define DSS_RD_3_MID	(SOC_DSS_RD_3_MID & SEC_ASI34_MASK)
#define DSS_RD_2_MID	(SOC_DSS_RD_2_MID & SEC_ASI34_MASK)
#define DSS_RD_1_MID	(SOC_DSS_RD_1_MID & SEC_ASI34_MASK)
#define DSS_RD_0_MID	(SOC_DSS_RD_0_MID & SEC_ASI34_MASK)
#define ISP_ISP_R8_MID	(SOC_ISP_ISP_R8_MID & SEC_ASI34_MASK)
#define ISP_ALL	((1 << ISP_1_ISP_CORE_0_MID) | (1 << ISP_1_ISP_CORE_1_MID) | (1 << ISP_1_ISP_CORE_2_MID) | (1 << ISP_1_ISP_CORE_3_MID) \
	| (1 << ISP_1_ISP_CORE_4_MID) | (1 << ISP_1_ISP_CORE_5_MID) | (1 << ISP_1_ISP_CORE_6_MID) | (1 << ISP_1_ISP_CORE_7_MID) \
	| (1 << ISP_2_ISP_CORE_0_MID) | (1 << ISP_2_ISP_CORE_1_MID) | (1 << ISP_2_ISP_CORE_2_MID) | (1 << ISP_2_ISP_CORE_3_MID) \
	| (1 << ISP_2_ISP_CORE_4_MID) | (1 << ISP_2_ISP_CORE_5_MID) | (1 << ISP_2_ISP_CORE_6_MID) | (1 << ISP_2_ISP_JPEG_MID) \
	| (1 << ISP_ISP_R8_MID))
#define DSS_ALL	((1 << DSS_CMDLIST_MID) | (1 << DSS_WR_1_MID) | (1 << DSS_WR_0_MID) | (1 << DSS_RD_8_MID) \
	| (1 << DSS_RD_7_MID) | (1 << DSS_RD_6_MID) | (1 << DSS_RD_5_MID) | (1 << DSS_RD_4_MID) \
	| (1 << DSS_RD_3_MID) | (1 << DSS_RD_2_MID) | (1 << DSS_RD_1_MID) | (1 << DSS_RD_0_MID))

#define IPP_SUBSYS_JPGENC_MID		(SOC_IPP_SUBSYS_JPGENC_MID & SEC_ASI34_MASK)
#define IPP_SUBSYS_CMDLIST_MID			(SOC_IPP_SUBSYS_CMDLIST_MID & SEC_ASI34_MASK)
#define IPP_SUBSYS_ORB_MID			(SOC_IPP_SUBSYS_ORB_MID & SEC_ASI34_MASK)
#define IPP_SUBSYS_ALL		((1 << IPP_SUBSYS_JPGENC_MID) | (1 << IPP_SUBSYS_CMDLIST_MID) | (1 << IPP_SUBSYS_ORB_MID))

/*ASI 1*/
#define NPU_0_MID		(SOC_NPU_0_MID & SEC_ASI1_MASK)
#define NPU_1_MID		(SOC_NPU_1_MID & SEC_ASI1_MASK)
#define NPU_2_MID		(SOC_NPU_2_MID & SEC_ASI1_MASK)
#define NPU_3_MID		(SOC_NPU_3_MID & SEC_ASI1_MASK)
#define NPU_ALL     ((1 << NPU_0_MID) | (1 << NPU_1_MID) | (1 << NPU_2_MID) | (1 << NPU_3_MID))

/*ASI 2*/
#define VENC1_MID	(SOC_VENC1_MID & SEC_ASI2_MASK)
#define VENC2_MID	(SOC_VENC2_MID & SEC_ASI2_MASK)
#define VDEC1_MID	(SOC_VDEC1_MID & SEC_ASI2_MASK)
#define VDEC2_MID	(SOC_VDEC2_MID & SEC_ASI2_MASK)
#define VDEC3_MID	(SOC_VDEC3_MID & SEC_ASI2_MASK)
#define VDEC4_MID	(SOC_VDEC4_MID & SEC_ASI2_MASK)
#define VDEC5_MID	(SOC_VDEC5_MID & SEC_ASI2_MASK)
#define VDEC6_MID	(SOC_VDEC6_MID & SEC_ASI2_MASK)
#define VENC_ALL	((1 << VENC1_MID) | (1 << VENC2_MID))
#define VDEC_ALL	((1 << VDEC1_MID) | (1 << VDEC2_MID) | (1 << VDEC3_MID) | (1 << VDEC4_MID) \
	| (1 << VDEC5_MID) | (1 << VDEC6_MID))
#define IVP32_DSP_DSP_CORE_INST_MID	(SOC_IVP32_DSP_DSP_CORE_INST_MID & SEC_ASI2_MASK)
#define IVP32_DSP_DSP_CORE_DATA_MID	(SOC_IVP32_DSP_DSP_CORE_DATA_MID & SEC_ASI2_MASK)
#define IVP32_DSP_DSP_DMA_MID		(SOC_IVP32_DSP_DSP_DMA_MID & SEC_ASI2_MASK)
#define IVP_ALL	((1 << IVP32_DSP_DSP_CORE_INST_MID) | (1 << IVP32_DSP_DSP_DMA_MID) | (1 << IVP32_DSP_DSP_CORE_DATA_MID))

/*ASI 5/6*/
#define FCM_M0_MID	(SOC_FCM_M0_MID & SEC_ASI56_MASK)
#define FCM_M1_MID	(SOC_FCM_M1_MID & SEC_ASI56_MASK)
#define CPU_ALL	((1 << FCM_M0_MID) | (1 << FCM_M1_MID))

/*ASI 8/9*/
#define GPU0_NON_DRM_MID	(SOC_GPU0_NON_DRM_MID & SEC_ASI89_MASK)
#define GPU0_DRM_MID		(SOC_GPU0_DRM_MID & SEC_ASI89_MASK)
#define GPU_ALL	((1 << GPU0_NON_DRM_MID) | (1 << GPU0_DRM_MID))

#define FORBID_MID	(0x0)
#define ALL_MID	(0xFFFFFFFF)

#define BIT(n) (1U << (n))
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

#define SOC_DMSS_ASI_RTL_INF2_ADDR(base, asi_base)    ((base) + (0x008+0x800*(asi_base)))
#define SOC_DMSS_ASI_SEC_RGN_MAP0_ADDR(base, sec_rgns, asi_base)  ((base) + (0x500+0x10*(sec_rgns)+0x800*(asi_base)))
#define SOC_DMSS_ASI_SEC_RGN_MAP1_ADDR(base, sec_rgns, asi_base)  ((base) + (0x504+0x10*(sec_rgns)+0x800*(asi_base)))
#define SOC_DMSS_ASI_SEC_MID_WR_ADDR(base, sec_rgns, asi_base)  ((base) + (0x508+0x10*(sec_rgns)+0x800*(asi_base)))
#define SOC_DMSS_ASI_SEC_MID_RD_ADDR(base, sec_rgns, asi_base)  ((base) + (0x50C+0x10*(sec_rgns)+0x800*(asi_base)))

#define ASI_MAX_RGN	(32)
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
        unsigned int  rtl_sec_rgn_num       : 6;  /* bit[0-5]  : ASI安全模块的regions个数：
                                                                 6'd0：无安全模块；
                                                                 6'd1：1regions；
                                                                 6'd2：2regions；
                                                                 6'd3：3regions；
                                                                 ……
                                                                 注意：当无安全模块时，安全功能相关寄存器无效。 */
        unsigned int  reserved_0            : 2;  /* bit[6-7]  : 保留。 */
        unsigned int  rtl_sec_chk_mid_width : 3;  /* bit[8-10] : ASI安全模块的MID检查位宽：
                                                                 0x0：无安全模块；
                                                                 0x1：只对MID[0]进行MID权限检查；
                                                                 0x2：只对MID[1:0]进行MID权限检查；
                                                                 ……
                                                                 0x5：只对MID[4:0]进行MID权限检查；
                                                                 注意：当无安全模块时，安全功能相关寄存器无效。 */
        unsigned int  reserved_1            : 1;  /* bit[11]   : 保留。 */
        unsigned int  rtl_mpu_chk_mid_width : 3;  /* bit[12-14]: MPU模块的MID检查位宽：
                                                                 0x0：无安全模块；
                                                                 0x1：只对MID[0]进行MID权限检查；
                                                                 0x2：只对MID[1:0]进行MID权限检查；
                                                                 ……
                                                                 0x5：只对MID[4:0]进行MID权限检查；
                                                                 0x6：只对MID[5:0]进行MID权限检查；
                                                                 注意：当无MPU模块时，MPU功能相关寄存器无效。 */
        unsigned int  reserved_2            : 1;  /* bit[15]   : 保留。 */
        unsigned int  rtl_rd_fifo_depth     : 5;  /* bit[16-20]: 读数据FIFO配置深度：
                                                                 0x0： 1 read transfer；
                                                                 0x1： 2 read transfer；
                                                                 ……
                                                                 0x1F：32 read transfer。 */
        unsigned int  reserved_3            : 11; /* bit[21-31]: 保留。 */
    } reg;
} SOC_DMSS_ASI_RTL_INF2_UNION;

#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_rgn_num_START        (0)
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_rgn_num_END          (5)
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_chk_mid_width_START  (8)
#define SOC_DMSS_ASI_RTL_INF2_rtl_sec_chk_mid_width_END    (10)
#define SOC_DMSS_ASI_RTL_INF2_rtl_mpu_chk_mid_width_START  (12)
#define SOC_DMSS_ASI_RTL_INF2_rtl_mpu_chk_mid_width_END    (14)
#define SOC_DMSS_ASI_RTL_INF2_rtl_rd_fifo_depth_START      (16)
#define SOC_DMSS_ASI_RTL_INF2_rtl_rd_fifo_depth_END        (20)

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
