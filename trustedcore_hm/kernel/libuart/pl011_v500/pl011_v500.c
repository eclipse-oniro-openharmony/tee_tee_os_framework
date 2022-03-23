/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: uart output, v500 uart hardware adaptor
 * Create: 2021-07
 */
#include <pl011_v500.h>

#include <uart_register.h>

#define UART_TIMEOUT 50000

#define UART_LSR_OFFSET  0x14
#define UART_TXFF_MASK   (8u)
#define UART_DATA_OFFSET 0xc

static uint32_t is_pl011_v500_ready(uintptr_t uart_addr)
{
    uint32_t timeout = UART_TIMEOUT;

    while ((*(uint32_t*)((uint8_t*)uart_addr + UART_LSR_OFFSET) & UART_TXFF_MASK) && (--timeout));

    if (timeout == 0)
        return 0;

    return 1;
}

uint32_t uart_v500_put_char(const unsigned char *ch, uint32_t max_bytes)
{
    return put_debug_char_common(ch, is_pl011_v500_ready, max_bytes, UART_DATA_OFFSET);
}
