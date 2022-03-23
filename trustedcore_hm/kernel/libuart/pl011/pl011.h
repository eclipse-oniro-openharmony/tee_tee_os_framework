/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: uart output, hw adaptor, pl011_general
 * Create: 2021-07
 */
#ifndef LIBUART_PL011_H
#define LIBUART_PL011_H

#include <stddef.h>
#include <stdint.h>

uint32_t pl011_put_char(const unsigned char *ch, uint32_t max_bytes);

#endif
