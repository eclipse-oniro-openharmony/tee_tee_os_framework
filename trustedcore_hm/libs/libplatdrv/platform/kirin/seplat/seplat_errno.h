/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:Define seplat error numbers.
 * Create: 2021/02/02
 */

#ifndef SEPLAT_ERRNO_H
#define SEPLAT_ERRNO_H

#include <tee_log.h>

#define SEPLAT_PRINT                tloge

#define SEPLAT_OK                   0x5A5A

/* seplat teeos err prefix */
#define ERR_PREFIX                  0xC4

#define ERR_MAKEUP(prefix, module, errcode) \
    (((prefix) << 24) | (((module) & 0xFF) << 16) | ((errcode) & 0xFFFF))

#define SEPLAT_ERRCODE(errcode) \
    ERR_MAKEUP(ERR_PREFIX, SEPLAT_THIS_MODULE, (errcode))

enum seplat_module_name {
    SEPLAT_MODULE_TEEOS          = 0x01,
    SEPLAT_MODULE_POWER          = 0x02,
    SEPLAT_MODULE_STATUS         = 0x03,
    SEPLAT_MODULE_HAL_GPIO       = 0x04,
    SEPLAT_MODULE_HAL_SPI        = 0x05,
    SEPLAT_MODULE_HAL_TIMER      = 0x06,
    SEPLAT_MODULE_HAL_THREAD     = 0x07,
    SEPLAT_MODULE_DATA_LINK      = 0x08,
    SEPLAT_MODULE_TEST           = 0xF1,
    SEPLAT_MODULE_DL_TEST        = 0xF2,
};

#endif /* SEPLAT_ERRNO_H */

