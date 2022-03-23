/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: hal api for tzasc
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#ifndef _TEE_DRV_TZASC_HAL_H_
#define _TEE_DRV_TZASC_HAL_H_

#include "hi_tee_drv_tzasc.h"

void tzasc_hal_init(void);
void tzasc_hal_enable(void);
void tzasc_hal_disable(void);
void tzasc_hal_config_res_region(unsigned int sp, unsigned long long mid);
void tzasc_hal_add_sec_region(hi_tee_tzasc_region *region);
void tzasc_hal_add_share_region(hi_tee_tzasc_share_region *region);
void tzasc_hal_share_release_config(const unsigned int en, unsigned long long mid);
void tzasc_hal_config_tzpc(void);
void tzasc_hal_security_check(void);
void tzasc_hal_get_share_region_end(unsigned long long *addr);

#endif /* _TEE_DRV_TZASC_HAL_H_ */
