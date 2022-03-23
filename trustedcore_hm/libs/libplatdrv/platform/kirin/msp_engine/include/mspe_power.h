/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declaration of mspe power.
 * Author: Security Engine
 * Create: 2020/10/27
 */
#ifndef MSPE_POWER_H
#define MSPE_POWER_H

#include <pal_types.h>

enum mspe_power_id {
	MSPE_POWER_ID_CDRM = 0,
	MSPE_POWER_ID_HDCP,
	MSPE_POWER_ID_SEC_BOOT,
	MSPE_POWER_ID_DICE,
	MSPE_POWER_ID_PRIP,
	MSPE_POWER_ID_HIAI,
	MSPE_POWER_ID_MAX
};

enum mspe_power_profile {
	MSPE_POWER_PROFILE0 = 0,
	MSPE_POWER_PROFILE1,
	MSPE_POWER_PROFILE2,
	MSPE_POWER_PROFILE3,
	MSPE_POWER_PROFILE_KEEP,     /* follow current hardware profile */
	MSPE_POWER_PROFILE_LOW_TEMP, /* low temperature */
	MSPE_POWER_PROFILE_MAX
};

enum mspe_power_onoff {
	MSPE_POWER_OFF = 0,
	MSPE_POWER_ON,
};

struct mspe_power_state {
	u32 onoff;
	u32 profile;
};

err_bsp_t mspe_power_on(u32 id, u32 profile);
err_bsp_t mspe_power_off(u32 id);
err_bsp_t mspe_power_suspend(void);

struct mspe_power_state mspe_power_get_hw_state(void);
struct mspe_power_state mspe_power_get_usr_state(u32 id);

typedef err_bsp_t (*mspe_power_hook_t)(u32 id, struct mspe_power_state old_state, struct mspe_power_state new_state);
void mspe_power_register_hook(mspe_power_hook_t hook);

#endif
