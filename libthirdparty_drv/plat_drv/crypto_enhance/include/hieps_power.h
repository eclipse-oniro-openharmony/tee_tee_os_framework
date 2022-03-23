/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This is header file for power contrl module.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#ifndef __HIEPS_POWER_H__
#define __HIEPS_POWER_H__

#include <eps_ddr_layout_define.h>
#include <soc_eps_ipc_interface.h>
#include <soc_acpu_baseaddr_interface.h>
#include <soc_pmctrl_interface.h>

/*===============================================================================
 *                                types/macros                                 *
===============================================================================*/
#define HIEPS_ON                           (0xA)
#define HIEPS_OFF                          (0x5)
#define HIEPS_POWEROFF_STATUS              (0x55555555)
#define HIEPS_BSP_CLK_SYNC_TIMEOUT         (500000) /* 500000 x 5us = 2.5s */
#define HIEPS_BSP_READY                    (0xA5A5A5A5)
#define HIEPS_BSP_READY_TIMEOUT            (500000) /* 500000 x 2us = 1s */

#define HIEPS_POWER_OFF_READY              (0x7B3F9846)
#define HIEPS_POWER_OFF_TIMEOUT            (500000) /* 500000 x 2us = 1s */

#define HIEPS_NON_COLD_BOOT               (0xF)
#define HIEPS_NON_COLD_BOOT_MASK          (0xF0000)

/******BEGIN of HiEPS CONFIG REG DEFINE******/
#define HIEPS_ARC_CTRL0_ADDR(base)         ((base) + (0x00))
#define HIEPS_NOC_CTRL_ADDR(base)          ((base) + (0x14))
#define HIEPS_ARC2NOC_AXCACHE_MUX_BIT      (24) /* bit24 */
#define HIEPS_CFG_ARC_WR_CACHE_MASK        (0x1FE00) /* bit[9-12]:read cache, bit[13-16]: write cache */
/******END of HiEPS CONFIG REG DEFINE******/

#define HIEPS_CLK_SRC_MASK                 (0x30000)
#define HIEPS_CLK_DIV_MASK                 (0x3F00000)

#define HIEPS_WAIT_ARC_RUN_TIMEOUT         (100000) /* 100000 x 2us = 200ms */
#define HIEPS_ARC_RUN_REQ_A_BIT            (0x1)
#define HIEPS_ARC_RUN_ACK_BIT              (0x1)

#define LOW_TEMPERATURE_FLAG_ADDR          (SOC_PMCTRL_PERI_CTRL4_ADDR(SOC_ACPU_PMC_BASE_ADDR))
#define LOW_TEMPERATURE_MASK               0xC000000 /* bit 27:26 */
#define NORMAL_TEMPERATURE                 0
#define LOW_TEMPERATURE_FLAG               0x387F69C8

#define HIEPS_BASE_DDR                     (HIEPS_DDR_SPACE_BASE_ADDR)
#define HIEPS_POWER_RESULT_ADDR            (EPS_POWER_RESULT_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_KDR_READY_FLAG_ADDR          (EPS_KDR_READY_FLAG_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_KDR_DATA_ADDR                (EPS_KDR_DATA_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_BSP_READY_ADDR               (EPS_BSP_END_FLAG_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_POWER_OFF_READY_ADDR         (EPS_POWER_OFF_READY_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))

/* Boot flag */
#define HIEPS_BOOT_SYS_IMG                 (0x5F478B4C)
#define HIEPS_IMG_BASE                     (EPS_SHARE_DDR_IMAGE_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_IMG_SIZE                     (HIEPS_SHARE_DDR_IMAGE_SIZE)
#define HIEPS_BOOT_START                   (EPS_ENHANCE_DDR_START_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_PROCESS_RUN                  (0xB3FE489C)
#define HIEPS_ROMPATCH_VALID_MAGIC         (0xAA55AA55)
#define HIEPS_BSP_CLS_SYNC_BEGIN           (0xAA55AA55)
#define HIEPS_BSP_CLS_SYNC_DONE            (0x55AA55AA)

#define HIEPS_BASE_DDR_ADDR                (HIEPS_DDR_REGION_BASE_ADDR(SOC_ACPU_EPS_IPC_BASE_ADDR))
#define HIEPS_BOOT_TYPE_ADDR               (BOOT_TYPE_FLAG_ADDR(SOC_ACPU_EPS_IPC_BASE_ADDR))
#define HIEPS_IMAGE_BASE_ADDR              (IMAGE_BASE_FLAG_ADDR(SOC_ACPU_EPS_IPC_BASE_ADDR))
#define HIEPS_IMAGE_SIZE_ADDR              (IMAGE_SIZE_FLAG_ADDR(SOC_ACPU_EPS_IPC_BASE_ADDR))
#define HIEPS_PROCESS_FLAG_ADDR            (PROCESS_FLAG_ADDR(SOC_ACPU_EPS_IPC_BASE_ADDR))
#define HIEPS_BOOT_START_ADDR              (DDR_BOOT_ADDR_FLAG(SOC_ACPU_EPS_IPC_BASE_ADDR))

#define HIEPS_ROMPATCH_FLAG_ADDR           (ROM_PATCH_MAGIC_ADDR(SOC_ACPU_EPS_IPC_BASE_ADDR))
#define HIEPS_ROMPATCH_DATA_ADDR           (ROM_PATCH_PACKAGE_ADDR_ADDR(SOC_ACPU_EPS_IPC_BASE_ADDR))
#define HIEPS_ROMPATCH_SIZE_ADDR           (ROM_PATCH_PACKAGE_SIZE_ADDR(SOC_ACPU_EPS_IPC_BASE_ADDR))
#define HIEPS_BSP_CLK_SYNC_ADDR            (BSP_CLK_SYNC_FLAG_ADDR(SOC_ACPU_EPS_IPC_BASE_ADDR))
#define HIEPS_BASE_CLK_ADDR                (SYSTEM_BASE_CLK_MHZ_ADDR(SOC_ACPU_EPS_IPC_BASE_ADDR))

#define HIEPS_ROM_CLK_FLAG_ADDR
#define HIEPS_BSP_CLK_WAIT_FLAG_ADDR

typedef enum {
	HIEPS_CLK_PPLL2   = 0,
	HIEPS_CLK_19M     = 1,
	HIEPS_CLK_PPLL0   = 2,
} hieps_clk_type;

typedef enum {
	HIEPS_POWER_SUCCESS = 0x5A,
	HIEPS_POWER_FAILED  = 0xA5,
} hieps_power_result;

typedef enum {
	HIEPS_ROM_PHASE = 0x3A4B5C6D,
	HIEPS_BSP_PHASE = 0xC5B4A392,
} hieps_phase_type;

typedef enum {
	HIEPS_CLK_DIV1 = 0,
	HIEPS_CLK_DIV2 = 1,
	HIEPS_CLK_DIV3 = 2,
	HIEPS_CLK_DIV4 = 3,
	HIEPS_CLK_DIV5 = 4,
	HIEPS_CLK_DIV6 = 5,
	HIEPS_CLK_DIV7 = 6,
	HIEPS_CLK_DIV8 = 7,
} hieps_clk_div_clk;

typedef enum {
	HIEPS_CLK_FREQUENCY_640M = 640,
	HIEPS_CLK_FREQUENCY_480M = 480,
	HIEPS_CLK_FREQUENCY_384M = 384,
	HIEPS_CLK_FREQUENCY_274M = 274,
} hieps_clk_frequency;

/* hieps profile id. */
typedef enum {
	PROFILE_080V  = 0, /* 0.8V */
	PROFILE_070V,      /* 0.7V */
	PROFILE_065V,      /* 0.65V */
	PROFILE_060V,	   /* 0.6V */
	PROFILE_KEEP,      /* keep profile no change when power on */
	MAX_PROFILE,
} hieps_profile_id;

/* hieps power vote id. */
typedef enum {
	CHINA_DRM = 0,
	HDCP,
	SEC_BOOT,
	DICE,
	PRIP,        /* privacy protection */
	HIAI,
	GP_API,
	MAX_POWER_ID,
} hieps_power_id;

/* hieps power status. */
typedef union {
	uint32_t value;
	struct {
		uint32_t china_drm:4;
		uint32_t hdcp:4;
		uint32_t sec_boot:4;
		uint32_t dice:4;
		uint32_t prip:4;
		uint32_t hiai:4;
		uint32_t reserved:8;
	} status;
} hieps_power_vote_status;

typedef struct {
	uint32_t profile_status;
	uint32_t profile_vote[MAX_POWER_ID];
} hieps_profile_status;

typedef struct {
	hieps_clk_frequency hieps_rom_clk;
	hieps_clk_div_clk hieps_rom_div;
	hieps_clk_frequency hieps_bsp_clk;
	hieps_clk_div_clk hieps_bsp_div;
} hieps_power_param_type;

/*===============================================================================
 *                                global objects                               *
===============================================================================*/


/*===============================================================================
 *                                  functions                                  *
===============================================================================*/
uint32_t hieps_power_on(uint32_t id, uint32_t profile_id);
uint32_t hieps_power_off(uint32_t id, uint32_t profile_id);
hieps_profile_status hieps_get_profile(void);
uint32_t hieps_poweron_process(const uint32_t profile);
void hieps_clear_power_status(void);
uint32_t hieps_get_power_status(void);

#endif /*  __HIEPS_POWER_H__ */
