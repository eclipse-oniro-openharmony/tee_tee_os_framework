/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secboot modem call, called by secboot TA
 * Author: modem-mcd
 * Create: 2020/12/04
 */

#include "secboot_modem_call.h"
#include "tee_defines.h"
#include "tee_log.h"
#include <drv_mod_call.h>

#define UNUSED(x) ((void)(x))

TEE_Result seb_bsp_modem_call(uint32_t paramtypes, TEE_Param params[PARAMS_COUNT])
{
    TEE_Result ret;

    if (!check_param_type(paramtypes, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("paramtypes is not valid\n");
        ret = TEE_ERROR_GENERIC;
        return ret;
    }

    ret = (TEE_Result)__bsp_modem_call(params[0].value.a, params[0].value.b, NULL, 0);

    return ret;
}

TEE_Result seb_bsp_modem_call_ext(uint32_t paramTypes, TEE_Param params[PARAMS_COUNT])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("paramTypes is not valid");
        ret = TEE_ERROR_GENERIC;
        return ret;
    }

    ret = (TEE_Result)__bsp_modem_call(params[0].value.a, params[0].value.b, params[1].memref.buffer,
        params[1].memref.size);

    return ret;
}
