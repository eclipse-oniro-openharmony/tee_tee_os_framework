/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: MTK SPI Test Source File
 * Author: tangjianbo
 * Create: 2020-01-21
 */
#include "spi.h"
#include "securec.h"

#define SPI_TEST_ADDR_VALUE 0x12345678
#define SPI_TEST_DATA_LEN   16
void spi_test(void)
{
    spi_init_func();
    int test_data[SPI_TEST_DATA_LEN] = {0};
    int recv_data[SPI_TEST_DATA_LEN] = {0};
    int i;
    int ret;

    (void)memset_s(&test_data, sizeof(test_data), SPI_TEST_ADDR_VALUE, sizeof(test_data));

    ret = spi_send(&test_data, &recv_data, SPI_TEST_DATA_LEN * sizeof(int), 0, 1);
    if (ret)
        dprintf(INFO, "spi_send failed,ret:%d", ret);

    for (i = 0; i < SPI_TEST_DATA_LEN; i++) {
        if (recv_data[i] != test_data[i]) {
            tloge("SpiRecv Check fail,rx:0x%x while tx:0x%x", recv_data[i], test_data[i]);
            ret++;
        }
    }
    if (ret == 0)
        tloge("spi_send succeed,ret:%d", ret);
}



