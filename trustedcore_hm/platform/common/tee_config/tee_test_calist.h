/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: test ca blacklist
 * Create: 2022-02-26
 */

#ifndef TEE_TEST_CALIST_H
#define TEE_TEST_CALIST_H

#ifdef CONFIG_TEST_CA_CHECK
#include <stdint.h>
uint32_t get_testca_blacklist_num(void);
const char **get_testca_blacklist(void);
#endif

#endif
