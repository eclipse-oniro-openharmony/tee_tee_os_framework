/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: tzasc api for itrustee
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#include "hi_tee_drv_tzasc.h"
#include "tee_drv_tzasc_hal.h"
#include "hi_tee_drv_os_hal.h"

void hi_tee_drv_tzasc_enable(void)
{
    tzasc_hal_enable();
}

void hi_tee_drv_tzasc_disable(void)
{
    tzasc_hal_disable();
}

void hi_tee_drv_tzasc_config_res_region(unsigned int sp, unsigned long long mid)
{
    tzasc_hal_config_res_region(sp, mid);
}

void hi_tee_drv_tzasc_add_sec_region(hi_tee_tzasc_region *region)
{
    if (region == NULL) {
        return;
    }

    tzasc_hal_add_sec_region(region);
}

void hi_tee_drv_tzasc_add_share_region(hi_tee_tzasc_share_region *region)
{
    if (region == NULL) {
        return;
    }

    tzasc_hal_add_share_region(region);
}

void hi_tee_drv_tzasc_share_release_config(const unsigned int en, unsigned long long mid)
{
    tzasc_hal_share_release_config(en, mid);
}

void hi_tee_drv_tzasc_config_tzpc(void)
{
    tzasc_hal_config_tzpc();
}

void hi_tee_drv_tzasc_security_check(void)
{
    tzasc_hal_security_check();
}

void hi_tee_drv_tzasc_init(void)
{
    tzasc_hal_init();
}

void hi_tee_drv_tzasc_get_share_region_end(unsigned long long *addr)
{
    if (addr == NULL) {
        return;
    }

    tzasc_hal_get_share_region_end(addr);
}
