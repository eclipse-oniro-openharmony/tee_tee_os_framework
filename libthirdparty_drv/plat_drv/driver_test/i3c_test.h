/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teeos i3c driver test code
 *              This program is support for I3C test work.
 * Author: hisilicon
 * Create: 2020-08-05
 */
#ifndef __SEC_OS_I3C_TEST_
#define __SEC_OS_I3C_TEST_

#include "bus_test.h"

#define	I3C_TEST_ERR 1
#define	I3C_TEST_OK 0
#define I3C4_TEST 4

#define I3C_TEST_MODE_I3C 0
#define I3C_TEST_MODE_I2C 1

enum i3c_test_para_index {
	I3C_PARA_0 = 0,
	I3C_PARA_1 = 1,
	I3C_PARA_2 = 2,
	I3C_PARA_3 = 3
};

enum i3c_test {
	I3C_TEST_BLOCK_WRITE = 1,
	I3C_TEST_BLOCK_READ = 2,
	I3C_TEST_WRITE = 3,
	I3C_TEST_READ = 4,
	I3C_TEST_MAX,
};

uint32_t i3c_driver_test(uint32_t num,
	const struct bus_test_para *parm_info);

#endif
