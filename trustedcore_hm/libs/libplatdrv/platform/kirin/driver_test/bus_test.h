/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teeos spi driver test code
 *              This program is support for SPI test work.
 * Author:
 * Create: 2020-08-05
 */
#ifndef __SEC_OS_BUS_TEST_
#define __SEC_OS_BUS_TEST_

#include <sre_typedef.h>

#define BUS_PARMSIZE                         64
#define BUS_PARMNUM                          6
#define BUS_TEEOS_SUCCESS                    0x0
#define BUS_TEEOS_ERROR                      0xd0
#define BUS_CA_CMD_ERROR                     0xf1

struct bus_test_para {
	char parm[BUS_PARMNUM][BUS_PARMSIZE];
	uint32_t parm_num;
};

enum cmd_list {
	BUS_TEST = 4,           /* General test cmd */
};

#endif
