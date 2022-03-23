/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: trng api head file
* Author: huawei
* Create: 2019/12/30
*/
#ifndef TRNG_API_H
#define TRNG_API_H

#include <stdint.h>

#define TRNG_SUCCESS                                    0x0
#define TRNG_FAIL                                       (-1)
#define TIME_OUT                                        0xFF
#define TRNG_ADDR_FAIL                                  0xF1
#define TRNG_ERR_STATUS_TIMEOUT                         0x060A0001U
#define TRNG_ERR_MEMCPY_FAILED                          0x060A0002U
#define TRNG_ERR_MEMSET_FAILED                          0x060A0003U
#define TRNG_NORMAL_LEN                                 0x10
#define TRNG_MAX_LEN                                    0x30000
#define SHIFT_LEN_32                                    32
#define RNG_BUFFER_SIZE                                 0x10
#define RNG_BUFFER_SIZE_MASK                            0x0F
#define RNG_BUFFER_BLSR                                 4
#define RNG_INDEX2                                      2

uint32_t trng_distribute(uint8_t *scr, uint32_t len);
uint32_t trng_get_random(uint8_t *trng_addr, uint32_t len);

#endif
