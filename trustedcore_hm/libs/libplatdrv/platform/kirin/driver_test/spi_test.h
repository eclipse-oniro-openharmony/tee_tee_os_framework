/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teeos spi driver test code
 *              This program is support for SPI test work.
 * Create: 2020-08-05
 */
#ifndef __SEC_OS_SPI_TEST_
#define __SEC_OS_SPI_TEST_

#define	SPI_TEST_ERR 1
#define SPI_TEST_OK 0

#include "bus_test.h"
#include <sre_typedef.h>

enum spi_test {
	SPI_TEST_DEP = 1,
	SPI_TEST_MAX,
};

enum spi_test_para_index {
	SPI_PARA_0 = 0
};


uint32_t spi_driver_test(uint32_t num,
	const struct bus_test_para *parm_info);

extern void null_cs_control(unsigned int value);

#endif
