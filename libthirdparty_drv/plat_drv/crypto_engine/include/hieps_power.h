/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This is header file for power contrl module.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#ifndef __HIEPS_POWER_H__
#define __HIEPS_POWER_H__

#include <eps_ddr_layout_define.h>
#include <soc_acpu_baseaddr_interface.h>
#include <soc_pmctrl_interface.h>
#include <hieps_powerctrl_plat.h>

#define HIEPS_ON                           0xA
#define HIEPS_OFF                          0x5
#define HIEPS_POWEROFF_STATUS              0x55555555
#define LOW_TEMPERATURE_FLAG_ADDR          (SOC_PMCTRL_PERI_CTRL4_ADDR(SOC_ACPU_PMC_BASE_ADDR))
#define LOW_TEMPERATURE_MASK               0xC000000 /* bit 27:26 */
#define NORMAL_TEMPERATURE                 0
#define LOW_TEMPERATURE_FLAG               0x387F69C8

#define HIEPS_BASE_DDR                     (HIEPS_DDR_SPACE_BASE_ADDR)
#define HIEPS_POWER_RESULT_ADDR            (EPS_POWER_RESULT_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_KDR_READY_FLAG_ADDR          (EPS_KDR_READY_FLAG_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_KDR_DATA_ADDR                (EPS_KDR_DATA_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))

enum hieps_power_result {
	HIEPS_POWER_SUCCESS = 0x5A,
	HIEPS_POWER_FAILED  = 0xA5,
};

/* hieps profile id. */
enum hieps_profile_id {
	PROFILE_080V  = 0, /* 0.8V */
	PROFILE_070V,      /* 0.7V */
	PROFILE_060V,      /* 0.6V */

	PROFILE_KEEP,      /* keep profile no change when power on */
	MAX_PROFILE,
};

#define PROFILE_CUSTOM PROFILE_KEEP /* compatible with phoenix */

/* hieps power vote id. */
enum hieps_power_id {
	CHINA_DRM = 0,
	HDCP,
	SEC_BOOT,
	DICE,
	PRIP,        /* privacy protection */
	HIAI,
	MAX_POWER_ID,
};

/* hieps power status. */
union hieps_power_vote_status {
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
};

struct hieps_profile_status {
	uint32_t profile_status;
	uint32_t profile_vote[MAX_POWER_ID];
};

uint32_t hieps_power_on(uint32_t id, uint32_t profile_id);
uint32_t hieps_power_off(uint32_t id, uint32_t profile_id);
struct hieps_profile_status hieps_get_profile(void);
uint32_t hieps_poweron_process(const uint32_t profile);
void hieps_clear_power_status(void);
uint32_t hieps_get_power_status(void);
void hieps_set_clk_frequency(uint32_t frq);
uint32_t hieps_get_clk_frequency(void);
uint32_t hieps_get_voted_nums(void);
uint32_t hieps_get_cur_profile(void);
void hieps_set_tcu_power_status(uint32_t data);

#endif /*  __HIEPS_POWER_H__ */
