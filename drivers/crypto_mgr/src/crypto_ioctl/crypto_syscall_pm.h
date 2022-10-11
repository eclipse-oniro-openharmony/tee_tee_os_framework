/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: crypto_mgr suspend and resume functions
 * Create: 2022-05
 */
#ifndef CRYPTO_SYSCALL_PM_H
#define CRYPTO_SYSCALL_PM_H

#include <stdint.h>
#include "crypto_driver_adaptor_ops.h"

int32_t crypto_mgr_suspend_call(const struct crypto_drv_ops_t *ops);
int32_t crypto_mgr_resume_call(const struct crypto_drv_ops_t *ops);

#endif
