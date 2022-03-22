/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teeos i2c driver test code
 *              This program is support for I2C test work.
 * Create: 2020-08-05
 */
#include <i2c_test.h>
#include <i2c.h>
#include <stdlib.h>
#include <tee_log.h>

#define I2C_TEST_PARAM_LEN    4
#define I2C_TEST_DATA_LEN     2
#define I2C_TEST_WRITE_LEN    2
#define I2C_TEST_READ_LEN     1
#define I2C_TEST_WRITE_VALUE  0x55

uint32_t i2c_driver_test(uint32_t num,
	const struct bus_test_para *parm_info)
{
	char *param[I2C_TEST_PARAM_LEN] = {0};
	uint32_t argv[I2C_TEST_PARAM_LEN] = {0};
	unsigned char data[I2C_TEST_DATA_LEN] = {0};
	uint32_t index;
	int32_t ret;
	uint16_t len = I2C_TEST_READ_LEN;

	if ((!parm_info) || (num > I2C_TEST_PARAM_LEN)) {
		tloge("%s:Invalid input!\n", __func__);
		return I2C_TEST_ERR;
	}

	for (index = 0; index < I2C_TEST_PARAM_LEN; index++) {
		param[index] = (char *)&(parm_info->parm[index + 1]);
		argv[index] = (uint32_t)atoi(param[index]);
		tloge("%s: argv %d is %u\n", __func__, index, argv[index]);
	}

	/* reg address */
	data[I2C_PARA_0] = argv[I2C_PARA_2];

	switch (argv[I2C_PARA_0]) {
	case I2C_TEST_READ:
		ret = hisi_i2c_read(argv[I2C_PARA_1],
			data, len, argv[I2C_PARA_3]);
		break;
	case I2C_TEST_READ_DIRECTLY:
		ret = hisi_i2c_read_directly(argv[I2C_PARA_1],
			data, len, argv[I2C_PARA_3]);
		break;
	case I2C_TEST_READ_REG16:
		ret = hisi_i2c_read_reg16(argv[I2C_PARA_1],
			data, len, argv[I2C_PARA_3]);
		break;
	case I2C_TEST_WRITE:
		len = I2C_TEST_WRITE_LEN;
		data[I2C_PARA_1] =  I2C_TEST_WRITE_VALUE;
		ret = hisi_i2c_write(argv[I2C_PARA_1],
			data, len, argv[I2C_PARA_3]);
		break;
	default:
		tloge("%s:Invalid index:%d!\n", __func__, argv[I2C_PARA_0]);
		return I2C_TEST_ERR;
	}

	if (ret != I2C_TEST_OK)
		tloge(" fail:%d!\n", ret);

	return ret;
}
