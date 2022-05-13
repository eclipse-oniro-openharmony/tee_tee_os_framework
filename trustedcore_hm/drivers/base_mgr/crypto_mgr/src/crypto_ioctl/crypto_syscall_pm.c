/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: implement crypto_mgr suspend and resume functions
 * Create: 2022-05
 */
#include "crypto_syscall_pm.h"

#include <hmlog.h>
#include "crypto_driver_adaptor.h"

int32_t crypto_mgr_suspend_call(const struct crypto_drv_ops_t *ops)
{
    if (ops == NULL) {
        hm_error("hardware engine register failed\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    if (ops->suspend == NULL) {
        hm_debug("crypto engine not need suspend\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = ops->suspend();
    if (ret != CRYPTO_SUCCESS)
        hm_error("crypto_mgr suspend failed\n");

    return ret;
}

int32_t crypto_mgr_resume_call(const struct crypto_drv_ops_t *ops)
{
    if (ops == NULL) {
        hm_error("hardware engine register failed\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    if (ops->resume == NULL) {
        hm_debug("crypto engine not need resume\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = ops->resume();
    if (ret != CRYPTO_SUCCESS)
        hm_error("crypto_mgr resume failed\n");

    return ret;
}
