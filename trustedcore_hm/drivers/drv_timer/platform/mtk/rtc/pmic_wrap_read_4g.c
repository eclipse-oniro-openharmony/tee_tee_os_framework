/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rtc timer pmic_wrap_read for 4g mtk platform
 * Author: zhangdeyao zhangdeyao@huawei.com
 * Create: 2020-11-23
 */
#include "pmic_wrap_read.h"
#include <hmlog.h>
#include <register_ops.h>
#include "timer_types.h"
#include "pmic_wrap_common.h"

#define WACS_CMD_RIGHT_SHIFT 1U
#define WACS_CMD_LEFT_SHIFT 16U

static int32_t pwrap_swinf_acc(uint32_t addr, uint32_t *rdata)
{
    uint32_t reg_rdata = 0;
    uint32_t wacs_cmd;
    int32_t  ret;

    /* Check argument validation */
    if ((addr & ~(INT_MAX_VALUE)) != TMR_DRV_SUCCESS)
        return -E_INVALID_ADDR;

    /* Wait for Software Interface FSM state to be IDLE */
    ret = wait_for_state_idle(TIMEOUT_IDLE, (uint32_t)(PMIF_VLD_CLR), (uint32_t)(PMIF_STA));
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("[PWRAP] fsm_idle fail\n");
        goto end;
    }

    wacs_cmd = (addr >> WACS_CMD_RIGHT_SHIFT) << WACS_CMD_LEFT_SHIFT;

    /* Send the command */
    write32(PMIC_WRAP_WACS2_CMD, wacs_cmd);

    /* Wait for Software Interface FSM to be WFVLDCLR, read the data and clear the valid flag */
    ret = wait_for_state_ready(TIMEOUT_READ, PMIF_VLD_CLR, &reg_rdata);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("[PWRAP] fsm_vldclr fail\n");
        goto end;
    }

    *rdata = (reg_rdata & INT_MAX_VALUE);
    write32(PMIF_STA, 0x1);
end:
    if (ret != TMR_DRV_SUCCESS)
        hm_error("pwrap swinf acc fail, ret=%d\n", ret);

    return ret;
}

/* external API for pmic_wrap user */
int32_t pwrap_read(uint32_t adr, uint32_t *rdata)
{
    if (rdata == NULL) {
        hm_error("invalid params\n");
        return TMR_DRV_ERROR;
    }

    return pwrap_swinf_acc(adr, rdata);
}
