/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: factory api. do crypto init and selftest.
 * Author: Security Engine
 * Create: 2020/11/07
 */
#ifndef MSPE_FACTORY_H
#define MSPE_FACTORY_H

#include <pal_types.h>

/*
 * for android factory test.
 * do crypto init and selftest.
 */
err_bsp_t mspe_factory_test(void);

#endif
