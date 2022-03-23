/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: delcaration of crypto init.
 * Author: Security Engine
 * Create: 2020/11/04
 */
#ifndef MSPE_CRYPTO_INIT_H
#define MSPE_CRYPTO_INIT_H

#include <pal_types.h>

err_bsp_t mspe_crypto_base_init(void);
err_bsp_t mspe_crypto_sm9_init(void);

/* all crypto ip init */
err_bsp_t mspe_crypto_init(void);

#endif
