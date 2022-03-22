/*
* Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
* Description: crypto soft engine error code for mbedtls lib
* Create: 2021-03-01
*/
#include <crypto_driver_adaptor.h>
#include <tee_err.h>

int32_t get_soft_crypto_error(int32_t tee_error, int32_t engine_error)
{
    if (engine_error == 0)
        return tee_error;
    else if (engine_error < 0)
        return TEE_EXT_ERROR_BASE | CRYPTO_MODULE_ERR_ID | (0 - engine_error);
    else
        return TEE_EXT_ERROR_BASE | CRYPTO_MODULE_ERR_ID | engine_error;
}
