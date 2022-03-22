/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: uart output, hw adaptor
 * Create: 2021-07
 */
#ifndef LIBUART_PL011_V500_H
#define LIBUART_PL011_V500_H

#include <stddef.h>
#include <stdint.h>

uint32_t uart_v500_put_char(const unsigned char *ch, uint32_t max_bytes);

#endif
