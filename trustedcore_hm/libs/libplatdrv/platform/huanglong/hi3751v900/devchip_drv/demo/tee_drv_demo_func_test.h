/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee os hal func test
 * Author: Hisilicon
 * Created: 2020-04-30
 */

#ifndef _TEE_DRV_DEMO_FUNC_TEST_H
#define _TEE_DRV_DEMO_FUNC_TEST_H

#include "hi_tee_drv_os_hal.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define TEST_SIZE_1K            1024
#define TEST_SIZE_4K            (4 * 1024)
#define TEST_SIZE_1M            (1024 * 1024)

#define TEST_SEC_MMZ_ADDR       0x22C00000
#define TEST_NOSEC_MEM_ADDR     0xF0000000

#define TEST_IO_ADDR            0x00D01000  /* TZASC */
#define TEST_IRQ                (104 + 32)  /* TZASC IRQ */

#define TEST_DATA1              0x12
#define TEST_DATA2              0x56

#define TEST_TIME_US_20MS       (20 * 1000)
#define TEST_TIME_MS_200MS      200
#define TEST_TIME_MS_500MS      500

#ifdef DEMO_TEST
#define test_printf(fmt, args...)       hi_tee_drv_hal_printf("######[%s][%d]: "fmt, __func__, __LINE__, ## args)
#else
#define test_printf(fmt, args...)
#endif

void tee_drv_demo_func_test(unsigned int cmd);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _TEE_DRV_DEMO_FUNC_TEST_H */

