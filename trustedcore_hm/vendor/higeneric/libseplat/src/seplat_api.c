/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description:APIs for sepalt.
 * Create: 2021/01/03
 */

#include "seplat_api.h"
#include "seplat.h"
#include "seplat_define.h"
#include "seplat_errno.h"
#include "seplat_status.h"

#ifdef CONFIG_SEPLAT_FEATURE
TEE_Result TEE_EXT_SEPLATIsAvailable(void)
{
    uint32_t ret;

    ret = seplat_get_dts_status();
    if (ret == SEPLAT_DTS_ABSENCE)
        tloge("%s:seplat is absence!\n", __func__);
    return ret;
}

TEE_Result TEE_EXT_SEPLATPowerOn(uint32_t vote_id)
{
    uint32_t ret;

    ret = seplat_power_ctrl(vote_id, SEPLAT_POWER_ON_CMD, SEPLAT_POWER_OP_BOOT);
    if (ret != SEPLAT_OK) {
        tloge("%s:power on failed:vote:%d, ret=%x.\n", __func__, vote_id, ret);
        return ret;
    }
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_SEPLATPowerOff(uint32_t vote_id)
{
    uint32_t ret;

    ret = seplat_power_ctrl(vote_id, SEPLAT_POWER_OFF_CMD, SEPLAT_POWER_OP_BOOT);
    if (ret != SEPLAT_OK) {
        tloge("%s:power off failed:vote:%d, ret=%x.\n", __func__, vote_id, ret);
        return ret;
    }
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_SEPLATReset(uint32_t vote_id, uint32_t op_type)
{
    uint32_t ret;

    ret = seplat_power_ctrl(vote_id, SEPLAT_POWER_RESET_CMD, op_type);
    if (ret != SEPLAT_OK) {
        tloge("%s:reset failed:vote:%d, ret=%x.\n", __func__, vote_id, ret);
        return ret;
    }
    return TEE_SUCCESS;
}
#else /* CONFIG_SEPLAT_FEATURE */
TEE_Result TEE_EXT_SEPLATIsAvailable(void)
{
    return TEE_ERROR_SERVICE_NOT_EXIST;
}

TEE_Result TEE_EXT_SEPLATPowerOn(uint32_t vote_id)
{
    (void)vote_id;
    return TEE_ERROR_SERVICE_NOT_EXIST;
}

TEE_Result TEE_EXT_SEPLATPowerOff(uint32_t vote_id)
{
    (void)vote_id;
    return TEE_ERROR_SERVICE_NOT_EXIST;
}

TEE_Result TEE_EXT_SEPLATReset(uint32_t vote_id, uint32_t op_type)
{
    (void)vote_id;
    (void)op_type;
    return TEE_ERROR_SERVICE_NOT_EXIST;
}

#endif /* CONFIG_SEPLAT_FEATURE */
