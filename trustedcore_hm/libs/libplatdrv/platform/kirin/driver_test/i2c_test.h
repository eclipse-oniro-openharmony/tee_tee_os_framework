/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teeos i2c driver test code
 *              This program is support for I2C test work.
 * Create: 2020-08-05
 */
#ifndef __SEC_OS_I2C_TEST_
#define __SEC_OS_I2C_TEST_

#include "bus_test.h"

#define	I2C_TEST_ERR 1
#define	I2C_TEST_OK 0

enum i2c_test_para_index {
	I2C_PARA_0 = 0,
	I2C_PARA_1 = 1,
	I2C_PARA_2 = 2,
	I2C_PARA_3 = 3
};

enum i2c_test {
	I2C_TEST_READ = 1,
	I2C_TEST_READ_DIRECTLY = 2,
	I2C_TEST_READ_REG16 = 3,
	I2C_TEST_WRITE = 4,
	I2C_TEST_MAX,
};

uint32_t i2c_driver_test(uint32_t num,
	const struct bus_test_para *parm_info);

#endif
