/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declaration of crypto in selftest.
 * Author: Security Engine
 * Create: 2020/11/04
 */
#ifndef MSPE_CRYPTO_SELFTEST_H
#define MSPE_CRYPTO_SELFTEST_H

#include <pal_types.h>

err_bsp_t mspe_crypto_base_selftest(void);
err_bsp_t mspe_crypto_sm9_selftest(void);

/* do all crypto ip selftest */
err_bsp_t mspe_crypto_selftest(void);

#endif
