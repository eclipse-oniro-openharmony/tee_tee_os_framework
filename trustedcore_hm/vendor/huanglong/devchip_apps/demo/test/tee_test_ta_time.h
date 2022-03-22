/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee time api test
 * Author: Hisilicon
 * Created: 2020-05-05
 */

#ifndef _TEE_TEST_TA_TIME_H
#define _TEE_TEST_TA_TIME_H

#include "tee_internal_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define SEC_PER_YEAR        (365 * 24 * 60 * 60)
#define SEC_PER_DAY         (24 * 60 * 60)
#define SEC_PER_HOUR        (60 * 60)
#define SEC_PER_MIN         60
#define MONTH_PER_YEAR      12

typedef struct {
    unsigned int year;
    unsigned char month;
    unsigned char day;
    unsigned char hour;
    unsigned char min;
    unsigned char sec;
    unsigned int ms;
} tee_date;

enum tee_test_cmd_time {
    TEE_TIME_CMD_GET_TEE_TIME = 0x300,
    TEE_TIME_CMD_GET_REE_TIME,
    TEE_TIME_CMD_WAIT,
};

TEE_Result ta_test_time(unsigned int cmd, unsigned int ms);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _TEE_TEST_TA_TIME_H */

