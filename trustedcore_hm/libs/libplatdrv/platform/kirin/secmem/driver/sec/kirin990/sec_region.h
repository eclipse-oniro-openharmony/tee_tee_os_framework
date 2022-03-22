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
#include <sec_region_ops.h>
#include <ddr_sec_feature.h>
#include <global_ddr_map.h>
#include <ddr_define.h>
#include <soc_dmss_interface.h>
#include <soc_mid.h>

/**********************************************************
 宏
**********************************************************/
typedef unsigned long long u64;
typedef unsigned int u32;

#define KERNEL_END_ADDR HISI_RESERVED_KERNEL_CAN_RUN_END

#define ASI_NUM_MAX	(DMSS_ASI_MAX)

/*kirin990 sec rgn granularity is 64K (addr low 16bit should be 0)*/
#define SEC_RGN_ADDR_SHIFT (16)
#define SEC_RGN_ADDR_MASK (0xFFFFULL)

#define ALL_ASI_MASK ((1U << ASI_NUM_MAX) - 1)

#define UNSEC_ADDR  (0)
#define SEC_ADDR    (1)

#define IVP_ASI_NUM    (1)
#define ISP_ASI_NUM    (3)
#define SUBSYS_ASI_NUM (5)
#define CPU_ASI_NUM    (6)
#define NPU_ASI_NUM    (8)

/* SUB_RGN_CFG begin */
/* hisi-cma for DRM/faceid 2D/TUI/Eid */
#define HISI_CMA_START HISI_RESERVED_DRM_CMA_BASE
#define HISI_CMA_END  (HISI_CMA_START + HISI_RESERVED_DRM_CMA_SIZE)
/* 3D faceid sec camera cma */
#define FACE_CMA_START HISI_RESERVED_IRIS_CMA_BASE
#define FACE_CMA_END  (FACE_CMA_START + HISI_RESERVED_IRIS_CMA_SIZE)
/* NPU tiny sec cma */
#define TINY_CMA_START HISI_RESERVED_TINY_CMA_BASE
#define TINY_CMA_END  (TINY_CMA_START + HISI_RESERVED_TINY_CMA_SIZE)

#define SUB_RGN_NUM(rgn_num)     (rgn_num - 1)
#define NORMAL_RGN_MAX_NUM  (2)
#define SUB_RGN_FEATURE_MAX (5)
#define FACE_SUB_RGN_MAX (2)
#define FACE_2D_FEATURE_NUM (2)
#define FACE_3D_FEATURE_NUM (3)

#define REG_BIT_NUM (32)
#define SUB_BIT_MAX_NUM (128)
#define SUB_BIT_RGN_NUM_MAX (3)
#define SUB_BIT_RGN_NUM_0 (0)
#define SUB_BIT_RGN_NUM_1 (1)
#define SUB_BIT_RGN_NUM_2 (2)
#define SUB_BIT_RGN_NUM_3 (3)
#define SUB_GRN_ZONE_1M (0x100000U)
#define SUB_GRN_ZONE_2M (0x200000U)

#define HIAI_UUID_NUM     0
#define TUI_UUID_NUM      1
#define SEC_ISP_UUID_NUM  2
#define SEC_FACE_UUID_NUM 3
#define SECBOOT_UUID_NUM  4
#define EID1_UUID_NUM     5
#define EID3_UUID_NUM     6
#define ION_UUID_NUM      7
#define LOW_MASK_16BIT    0xffff
#define UUID_INITIALIZER  { 0 }
#define UUID_NOT_GET      0
#define UUID_GET          1
#define TA_STATE_NORMAL   0
#define TA_STATE_CRASHED  1

#define BITS_WIDTH_MASK(num)                  ((u32)(((1UL << (num)) - 1)))
#define VALUE_SHIFT_WIDTH(value, width_bit)   ((u32)((value) << (width_bit)))
#ifdef WITH_CHIP_CS2
#define ASI_NUM_BYPASS(asi_num) ((ASI_NUM_2 == asi_num) || (ASI_NUM_4 == asi_num) || (ASI_NUM_7 == asi_num) || (ASI_NUM_9 == asi_num) \
	|| (ASI_NUM_14 == asi_num) || (ASI_NUM_15 == asi_num) || (ASI_NUM_16 == asi_num))
#else
#define ASI_NUM_BYPASS(asi_num) ((ASI_NUM_2 == asi_num) || (ASI_NUM_4 == asi_num) || (ASI_NUM_7 == asi_num) || (ASI_NUM_9 == asi_num) \
	|| (ASI_NUM_11 == asi_num) || (ASI_NUM_12 == asi_num) || (ASI_NUM_13 == asi_num))
#endif

enum {
	ASI_NUM_0 = 0,
	ASI_NUM_1,
	ASI_NUM_2,
	ASI_NUM_3,
	ASI_NUM_4,
	ASI_NUM_5,
	ASI_NUM_6,
	ASI_NUM_7,
	ASI_NUM_8,
	ASI_NUM_9,
	ASI_NUM_10,
	ASI_NUM_11,
	ASI_NUM_12,
	ASI_NUM_13,
#ifdef WITH_CHIP_CS2
	ASI_NUM_14,
	ASI_NUM_15,
	ASI_NUM_16,
#endif
};

typedef enum {
	ASI_NUM_TYPE_0 = 0,
	ASI_NUM_TYPE_1n2,
	ASI_NUM_TYPE_3n4,
	ASI_NUM_TYPE_5,
	ASI_NUM_TYPE_6n7,
	ASI_NUM_TYPE_8n9,
#ifndef WITH_CHIP_CS2
	ASI_NUM_TYPE_10n11n12n13,
#else
	ASI_NUM_TYPE_10,
	ASI_NUM_TYPE_11,
	ASI_NUM_TYPE_12,
	ASI_NUM_TYPE_13n14n15n16,
#endif
	ASI_NUM_TYPE_MAX,
} ASI_NUM_TYPE;

/*one region*/
typedef struct {
	unsigned int rgn_en:1;
	unsigned int attri:4;
	unsigned long long start_addr;
	unsigned long long end_addr;
	unsigned int mid_wr;
	unsigned int mid_rd;
} SEC_RGN_CFG;

typedef struct {
	enum SEC_FEATURE sec_feature;
	u32 region_num;
	u64 start_addr;
	u64 end_addr;
	u32 granularity_size;
} SUB_RGN_CFG;

typedef struct {
	enum SEC_FEATURE sec_feature;
	u32 region_num;
	SEC_RGN_CFG sec_rgn[ASI_NUM_TYPE_MAX];
} NORMAL_RGN_CFG;
/* SUB_RGN_CFG end */

/*KIRIN990 MID bit[0-4]*/
/*ASI 1/2*/
#define IVP32_DSP_DSP_CORE_INST_MID	(SOC_IVP32_DSP_DSP_CORE_INST_MID & SEC_ASI12_MASK)
#define IVP32_DSP_DSP_DMA_MID		(SOC_IVP32_DSP_DSP_DMA_MID & SEC_ASI12_MASK)
#define IVP32_DSP_DSP_CORE_DATA_MID	(SOC_IVP32_DSP_DSP_CORE_DATA_MID & SEC_ASI12_MASK)
#define IVP_ALL	((1 << IVP32_DSP_DSP_CORE_INST_MID) | (1 << IVP32_DSP_DSP_DMA_MID) | (1 << IVP32_DSP_DSP_CORE_DATA_MID))

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
#define ISP_ALL	((1 << ISP_1_ISP_CORE_0_MID) | (1 << ISP_1_ISP_CORE_1_MID) | (1 << ISP_1_ISP_CORE_2_MID) | (1 << ISP_1_ISP_CORE_3_MID) \
        | (1 << ISP_1_ISP_CORE_4_MID) | (1 << ISP_1_ISP_CORE_5_MID) | (1 << ISP_1_ISP_CORE_6_MID) | (1 << ISP_1_ISP_CORE_7_MID) \
        | (1 << ISP_2_ISP_CORE_0_MID) | (1 << ISP_2_ISP_CORE_1_MID) | (1 << ISP_2_ISP_CORE_2_MID) | (1 << ISP_2_ISP_CORE_3_MID))

#define IPP_SUBSYS_JPGENC_MID		(SOC_IPP_SUBSYS_JPGENC_MID & SEC_ASI34_MASK)
#define IPP_SUBSYS_JPGDEC_MID		(SOC_IPP_SUBSYS_JPGDEC_MID & SEC_ASI34_MASK)
#define IPP_SUBSYS_FD_MID			(SOC_IPP_SUBSYS_FD_MID & SEC_ASI34_MASK)
#define IPP_SUBSYS_CPE_MID			(SOC_IPP_SUBSYS_CPE_MID & SEC_ASI34_MASK)
#define IPP_SUBSYS_SLAM_MID			(SOC_IPP_SUBSYS_SLAM_MID & SEC_ASI34_MASK)
#define IPP_SUBSYS_ALL		((1 << IPP_SUBSYS_JPGENC_MID) | (1 << IPP_SUBSYS_JPGDEC_MID) \
        | (1 << IPP_SUBSYS_FD_MID) | (1 << IPP_SUBSYS_CPE_MID) | (1 << IPP_SUBSYS_SLAM_MID))

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
#ifdef WITH_CHIP_CS2
#define DSS_RD_0_MID	(SOC_DSS_RD_0_DSS_ATGM_MID & SEC_ASI34_MASK)
#else
#define DSS_RD_0_MID	(SOC_DSS_RD_0_MID & SEC_ASI34_MASK)
#endif
#define DSS_ALL	((1 << DSS_CMDLIST_MID) | (1 << DSS_WR_1_MID) | (1 << DSS_WR_0_MID) | (1 << DSS_RD_8_MID) \
        | (1 << DSS_RD_7_MID) | (1 << DSS_RD_6_MID) | (1 << DSS_RD_5_MID) | (1 << DSS_RD_4_MID) \
        | (1 << DSS_RD_3_MID) | (1 << DSS_RD_2_MID) | (1 << DSS_RD_1_MID) | (1 << DSS_RD_0_MID))

/*ASI 5*/
#ifdef WITH_CHIP_CS2
#define DJTAG_M_MID		(SOC_DJTAG_M_TOP_CSSYS_MID & SEC_ASI5_MASK)
#else
#define DJTAG_M_MID		(SOC_DJTAG_M_MID & SEC_ASI5_MASK)
#endif
#define CC712_MID		(SOC_CC712_MID & SEC_ASI5_MASK)
#ifdef WITH_CHIP_CS2
#define TOP_CSSYS_MID	(SOC_DJTAG_M_TOP_CSSYS_MID & SEC_ASI5_MASK)
#else
#define TOP_CSSYS_MID	(SOC_TOP_CSSYS_MID & SEC_ASI5_MASK)
#endif
#define DMAC_MID		(SOC_DMAC_MID & SEC_ASI5_MASK)
#define IOMCU_M7_MID    (SOC_IOMCU_M7_MID & SEC_ASI5_MASK)
#ifdef WITH_CHIP_CS2
#define IOMCU_DMA_MID   (SOC_IOMCU_DMA_AO_TCP_MID & SEC_ASI5_MASK)
#else
#define IOMCU_DMA_MID   (SOC_IOMCU_DMA_MID & SEC_ASI5_MASK)
#endif
#define FD_UL_MID       (SOC_FD_UL_MID & SEC_ASI5_MASK)

/*ASI 6/7*/
#define FCM_M0_MID			(SOC_FCM_M0_MID & SEC_ASI67_MASK)
#define FCM_M1_MID			(SOC_FCM_M1_MID & SEC_ASI67_MASK)
#define CPU_ALL				((1 << FCM_M0_MID) | (1 << FCM_M1_MID))

/*ASI 8/9*/
#ifdef WITH_CHIP_CS2
#define NPU0_MID	(SOC_NPU_NPU_ATGM_NPU_MID & SEC_ASI89_MASK)
#define NPU1_MID	(SOC_NPU_NPU_MID & SEC_ASI89_MASK)
#else
#define NPU0_MID	(SOC_NPU0_MID & SEC_ASI89_MASK)
#define NPU1_MID	(SOC_NPU1_MID & SEC_ASI89_MASK)
#endif
#define NPU_ALL     ((1 << NPU0_MID) | (1 << NPU1_MID))
#ifdef WITH_CHIP_CS2
#define MPU_NPU0_MID (SOC_NPU_NPU_ATGM_NPU_MID & TZMP2_ASI89_MASK)
#define MPU_NPU1_MID (SOC_NPU_NPU_MID & TZMP2_ASI89_MASK)
#else
#define MPU_NPU0_MID (SOC_NPU0_MID & TZMP2_ASI89_MASK)
#define MPU_NPU1_MID (SOC_NPU1_MID & TZMP2_ASI89_MASK)
#endif
#define MPU_NPU_ALL  ((1 << MPU_NPU0_MID) | (1 << MPU_NPU1_MID))

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

#define ASI_MAX_RGN	(32)
#define INVALID_REGION_INDEX		0x5e5e5e5e /*invalid index definition of region.*/

#define UNUSED(x) ((void)(x))

/**********************************************************
 结构体
**********************************************************/
enum {
	RW_FORBID = 0,        /* can't read or write in sec and un_sec*/
	UNSEC_WR = 0x1,    /* unsec write */
	UNSEC_RD = 0x2,     /* unsec read */
	SEC_WR = 0x4,      /* sec write */
	SEC_RD = 0x8,       /* sec read */
};

/**********************************************************
 函数接口
**********************************************************/

#endif
