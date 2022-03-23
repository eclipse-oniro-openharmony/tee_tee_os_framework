/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key transfer between GP and software engine
 * Create: 2020-11-09
 */

#include "km_defines.h"
#include "keymaster_defs.h"
#include "km_crypto_adaptor.h"
static keymaster_uint2uint g_gp2sw_ec_curve[] = {
    { TEE_ECC_CURVE_NIST_P192, NIST_P192 },
    { TEE_ECC_CURVE_NIST_P224, NIST_P224 },
    { TEE_ECC_CURVE_NIST_P256, NIST_P256 },
    { TEE_ECC_CURVE_NIST_P384, NIST_P384 },
    { TEE_ECC_CURVE_NIST_P521, NIST_P521 }
};

int32_t ec_nist_curve2swcurve(TEE_ECC_CURVE ec_curve, uint32_t *sw_ec_curve)
{
    if (sw_ec_curve == NULL) {
        tloge("null pointer\n");
        return -1;
    }
    if (look_up_table(g_gp2sw_ec_curve, sizeof(g_gp2sw_ec_curve) / sizeof(keymaster_uint2uint),
        ec_curve, sw_ec_curve) != TEE_SUCCESS) {
        tloge("invalid nist ec curve %d\n", ec_curve);
        return -1;
    }
    return 0;
}