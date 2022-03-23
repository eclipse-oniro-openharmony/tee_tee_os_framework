/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secure flash module driver.
 * Create: 2019/9/3
 */

#ifndef _SECFLASH_DATA_LINK_TEST_H_
#define _SECFLASH_DATA_LINK_TEST_H_

#include "types.h"
#ifdef SECFLASH_TEE
#include "sre_typedef.h"
#endif

/* NOTE only open in debug version for stub test */
#ifdef SECFLASH_DATA_LINK_TEST
uint32_t secflash_datalink_test(uint32_t function_id, uint32_t param1, uint32_t param2);
#endif
#endif
