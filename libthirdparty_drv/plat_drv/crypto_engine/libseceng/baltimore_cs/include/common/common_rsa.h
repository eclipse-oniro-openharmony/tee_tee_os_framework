/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: rsa common data
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2019/07/22
 */
#ifndef __COMMON_RSA_H__
#define __COMMON_RSA_H__
#include <common_define.h>

#define RSA_WIDTH_STEP                   64
#define RSA_WIDTH_256                    256
#define RSA_WIDTH_384                    384
#define RSA_WIDTH_512                    512
#define RSA_WIDTH_576                    576
#define RSA_WIDTH_768                    768
#define RSA_WIDTH_1024                   1024
#define RSA_WIDTH_1152                   1152
#define RSA_WIDTH_1976                   1976
#define RSA_WIDTH_1984                   1984
#define RSA_WIDTH_2048                   2048
#define RSA_WIDTH_3072                   3072
#define RSA_WIDTH_4096                   4096
#define RSA_WIDTH_MAX                    (RSA_WIDTH_4096)
#define RSA_WIDTH_8192                   8192
#define RSA_WIDTH_CLRMAX                 0x1F

#define RSA_WIDTH_ALIGN(w)       MAX(BIT_ALIGN(w, 6), RSA_WIDTH_256)

#endif /* end of __COMMON_RSA_H__ */
