/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teeos i3c driver test code
 *              This program is support for I3C test work.
 * Author:
 * Create: 2020-08-05
 */
#include <i3c_test.h>
#include <i3c.h>
#include <stdlib.h>
#include <tee_log.h>

#define I3C_TEST_PARAM_LEN     4
#define I3C_TEST_DATA_LEN      2
#define I3C_TEST_READ_LEN      1
#define I3C_TEST_WRITE_LEN     2
#define I2C_TEST_WRITE_VALUE   0x55

uint32_t i3c_driver_test(uint32_t num,
	const struct bus_test_para *parm_info)
{
	char *param[I3C_TEST_PARAM_LEN] = {0};
	uint32_t argv[I3C_TEST_PARAM_LEN] = {0};
	unsigned char data[I3C_TEST_DATA_LEN] = {0};
	uint32_t index;
	int32_t ret;
	uint16_t len = I3C_TEST_READ_LEN;

	if ((!parm_info) || (num > I3C_TEST_PARAM_LEN)) {
		tloge("%s:Invalid input!\n", __func__);
		return I3C_TEST_ERR;
	}

	for (index = 0; index < I3C_TEST_PARAM_LEN; index++) {
		param[index] = (char *)&(parm_info->parm[index + 1]);
		argv[index] = (uint32_t)atoi(param[index]);
		tloge("%s: argv %d is %u\n", __func__, index, argv[index]);
	}

	hisi_i3c_init(argv[I3C_PARA_1]);

	switch (argv[I3C_PARA_0]) {
	case I3C_TEST_BLOCK_WRITE:
		ret = hisi_i3c_block_write(argv[I3C_PARA_1], argv[I3C_PARA_2],
			data, len, I3C_TEST_MODE_I2C);
		break;
	case I3C_TEST_BLOCK_READ:
		ret = hisi_i3c_block_read(argv[I3C_PARA_1],
			argv[I3C_PARA_2], data, len, I3C_TEST_MODE_I2C);
		break;
	case I3C_TEST_WRITE:
		ret = hisi_i3c_write(argv[I3C_PARA_1], argv[I3C_PARA_2],
			argv[I3C_PARA_3], data, len, I3C_TEST_MODE_I2C);
		break;
	case I3C_TEST_READ:
		len = I3C_TEST_WRITE_LEN;
		ret = hisi_i3c_read(argv[I3C_PARA_1], argv[I3C_PARA_2],
			argv[I3C_PARA_3], data, len, I3C_TEST_MODE_I2C);
		break;
	default:
		tloge("%s:Invalid index:%d!\n", __func__, argv[I3C_PARA_0]);
		return I3C_TEST_ERR;
	}

	if (ret != I3C_TEST_OK)
		tloge(" fail:%d!\n", ret);

	hisi_i3c_exit(argv[I3C_PARA_1]);

	return ret;
}
