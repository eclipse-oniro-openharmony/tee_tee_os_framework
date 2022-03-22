/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for data link test.
 * Create: 2020/01/14
 */

#ifndef SEPLAT_DL_TEST_ENTRY_H
#define SEPLAT_DL_TEST_ENTRY_H

#include <stdint.h>

enum seplat_errcode_dl_test {
    SEPLAT_ERRCODE_CHAN_PARAM_NULL           = 0x01,
};

#ifdef CONFIG_FEATURE_SEPLAT_TEST
uint32_t dl_test_callback_init(void);
#else
#define DL_TEST_OK 0x5A5A
uint32_t dl_test_callback_init(void)
{
    return DL_TEST_OK;
}
#endif
#endif /* __MSPC_TEST_H__ */