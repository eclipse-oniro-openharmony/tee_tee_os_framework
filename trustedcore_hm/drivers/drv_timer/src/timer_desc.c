/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Desc timer function
 * Create: 2019-08-20
 */
#include "timer_desc.h"
#include <hmlog.h>
#include <hongmeng.h>
#include <drv_module.h>
#include "timer_types.h"
#include "timer_pm.h"

#define REVSER_VALUE 0
DECLARE_TC_TIMER(timer_cfg,
                 REVSER_VALUE,
                 REVSER_VALUE,
                 REVSER_VALUE,
                 TC_DRV_MODULE_INIT,
                 NULL,
                 NULL,
                 NULL,
                 timer_suspend,
                 timer_resume);
static const struct tc_drv_desc_timer *g_tc_drv[] = {
    &__drv_desc_timer_cfg,
};

int32_t tc_drv_init(void)
{
    uint32_t i;
    int32_t ret;

    hm_debug("initialize drivers:\n");

    for (i = 0; i < ARRAY_SIZE(g_tc_drv); i++) {
        hm_debug("\t%s\n", g_tc_drv[i]->name);
        if (g_tc_drv[i]->init != NULL) {
            ret = g_tc_drv[i]->init();
            if (ret != TMR_DRV_SUCCESS)
                return ret;
        }
    }

    return TMR_DRV_SUCCESS;
}

void tc_drv_sp(uint32_t flag)
{
    uint32_t i;

    for (i = 0; i < ARRAY_SIZE(g_tc_drv); i++) {
        if (g_tc_drv[i]->suspend == NULL)
            continue;

        (void)g_tc_drv[i]->suspend(flag);
        hm_debug("driver \"%s\" suspend\n", g_tc_drv[i]->name);
    }
}

void tc_drv_sr(uint32_t flag)
{
    uint32_t i;
    int32_t ret;

    for (i = 0; i < ARRAY_SIZE(g_tc_drv); i++) {
        if (g_tc_drv[i]->resume == NULL)
            continue;

        ret = g_tc_drv[i]->resume(flag);
        if (ret != TMR_DRV_SUCCESS)
            hm_error("ERROR:driver resume failed\n");
    }
}
