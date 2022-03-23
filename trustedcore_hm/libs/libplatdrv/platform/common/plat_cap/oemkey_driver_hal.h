/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:  ormkey API at driver adaptor.
 * Create: 2021-07
 */
#ifndef OEMKEY_DRIVER_ADAPTOR_H
#define OEMKEY_DRIVER_ADAPTOR_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define OEMKEY_SIZE 16

enum oemkey_engine {
    SEC_OEMKEY_FLAG,
};

enum oemkey_err {
    OEMKEY_NOT_SUPPORTED        = -1,
    OEMKEY_CIPHERTEXT_INVALID   = -2,
    OEMKEY_BAD_FORMAT           = -3,
    OEMKEY_BAD_PARAMETERS       = -4,
    OEMKEY_BAD_STATE            = -5,
    OEMKEY_SHORT_BUFFER         = -6,
    OEMKEY_OVERFLOW             = -7,
    OEMKEY_MAC_INVALID          = -8,
    OEMKEY_SIGNATURE_INVALID    = -9,
    OEMKEY_ERROR_SECURITY       = -10,
    OEMKEY_ERROR_OUT_OF_MEMORY  = -11,
    OEMKEY_SUCCESS              = 0,
};

struct oemkey_ops_t {
    uint32_t (*get_provision_key)(uint8_t *poemkey, size_t key_size);
};

int32_t register_oemkey_ops(uint32_t engine, const struct oemkey_ops_t *ops);
#endif
