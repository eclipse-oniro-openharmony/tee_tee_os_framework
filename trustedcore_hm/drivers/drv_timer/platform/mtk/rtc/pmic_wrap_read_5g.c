/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rtc timer pmic_wrap_read for 5g mtk platform
 * Author: zhangdeyao zhangdeyao@huawei.com
 * Create: 2020-11-23
 */

#include "pmic_wrap_read.h"
#include <hmlog.h>
#include <register_ops.h>
#include "timer_types.h"
#include "pmic_wrap_common.h"

static int32_t pwrap_swinf_acc(uint32_t addr, uint32_t *rdata)
{
    uint32_t reg_rdata;
    int32_t  ret;

    /* Check argument validation */
    if ((addr & ~(INT_MAX_VALUE)) != TMR_DRV_SUCCESS)
        return -E_INVALID_ADDR;

    reg_rdata = read32(PMIF_STA + PMIF_READ);
    if (get_swinf_init_done(reg_rdata) != WACS_INIT_DONE) {
        hm_error("[PWRAP] init not finish\n");
        ret = -E_NOT_INIT_DONE;
        goto end;
    }

    /* Wait for Software Interface FSM state to be IDLE */
    ret = wait_for_state_idle(TIMEOUT_IDLE, (uint32_t)(PMIF_STA + PMIF_READ), (uint32_t)(PMIF_VLD_CLR + PMIF_READ));
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("[PWRAP] fsm_idle fail\n");
        goto end;
    }

    /* Send the command */
    write32(PMIF_ACC + PMIF_READ, addr);

    /* Wait for Software Interface FSM to be WFVLDCLR, read the data and clear the valid flag */
    ret = wait_for_state_ready(TIMEOUT_READ, PMIF_STA + PMIF_READ, &reg_rdata);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("[PWRAP] fsm_vldclr fail\n");
        goto end;
    }

    *rdata = read32(PMIF_RDATA_31_0 + PMIF_READ);
    write32(PMIF_VLD_CLR + PMIF_READ, 0x1);

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
