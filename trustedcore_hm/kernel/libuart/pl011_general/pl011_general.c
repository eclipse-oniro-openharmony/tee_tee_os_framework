/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: uart output, hw adaptor
 * Create: 2021-07
 */

#include <pl011_general.h>

#include <uart_register.h>

#define UART_LSR_OFFSET 0x14
#define UART_TXFF_MASK  (1u << 5)

static uint32_t is_pl011_general_ready(uintptr_t uart_addr)
{
    udelay(0x1000);
    return (*(uint32_t*)(uintptr_t)((uint64_t)uart_addr + UART_LSR_OFFSET) & UART_TXFF_MASK);
}

uint32_t pl011_general_put_char(const unsigned char *ch, uint32_t max_bytes)
{
    return put_debug_char_common(ch, is_pl011_general_ready, max_bytes, 0);
}
