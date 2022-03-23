/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
 * Description: secboot verify, called by secboot TA
 * Author: modem-dev
 * Create: 2020/11/18
 */

#include "secboot_load_modem_teeos.h"
#include "tee_defines.h"
#include "tee_log.h"
#include <drv_mod_call.h>

#define UNUSED(x) ((void)(x))

#ifdef CONFIG_LOAD_MODEM_TEEOS
TEE_Result seb_modem_load_modem_teeos(uint32_t paramtypes, TEE_Param params[PARAMS_COUNT])
{
    int32_t ret;
    UNUSED(paramtypes);
    UNUSED(params);

    ret = load_drv_mod("platdrv", "platdrv_libsec_modem.so");
    if (ret == 0) {
        tlogd("%s, load modem teeos success\n", __func__);
    } else {
        tloge("%s, load modem teeos failed, ret = 0x%x\n", __func__, ret);
    }

    return (TEE_Result)ret;
}
#else
TEE_Result seb_modem_load_modem_teeos(uint32_t paramtypes, TEE_Param params[PARAMS_COUNT])
{
    UNUSED(paramtypes);
    UNUSED(params);
    tloge("%s, load modem teeos is stub\n", __func__);
    return (TEE_Result)0;
}
#endif

TEE_Result seb_modem_unload_modem_teeos(uint32_t paramtypes, TEE_Param params[PARAMS_COUNT])
{
    UNUSED(paramtypes);
    UNUSED(params);
    tloge("%s, unload modem teeos is stub\n", __func__);
    return (TEE_Result)0;
}
