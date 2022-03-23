/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: product uuid declare
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */
#ifndef PRODUCT_CONFIG_H
#define PRODUCT_CONFIG_H

#include "tee_test_uuid.h"

/* 76b0e9db-fefa-46b5-8f49-73b0031d32c1 */
#define TEE_SERVICE_DIM                                    \
    {                                                      \
        0x76b0e9db, 0xfefa, 0x46b5,                        \
        {                                                  \
            0x8f, 0x49, 0x73, 0xb0, 0x03, 0x1d, 0x32, 0xc1 \
        }                                                  \
    }

/* 89559f25-9989-4215-85b0-4db188025956 */
#define TEE_SERVICE_MINITPM                                \
    {                                                      \
        0x89559f25, 0x9989, 0x4215,                        \
        {                                                  \
            0x85, 0xb0, 0x4d, 0xb1, 0x88, 0x02, 0x59, 0x56 \
        }                                                  \
    }

/* ae9b2c33-eecd-49db-8df9-9638ba4c2024 */
#define TEE_SERVICE_FTPM                                   \
    {                                                      \
        0xae9b2c33, 0xeecd, 0x49db,                        \
        {                                                  \
            0x8d, 0xf9, 0x96, 0x38, 0xba, 0x4c, 0x20, 0x24 \
        }                                                  \
    }
#endif
