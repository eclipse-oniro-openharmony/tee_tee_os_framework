/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: uart output, hw adaptor
 * Create: 2020-12
 */

#include <pl011.h>

#include <uart_register.h>

#define UART_LSR_OFFSET 0x18
#define UART_TXFF_MASK  (1u << 5)

static uint32_t is_pl011_ready(uintptr_t uart_addr)
{
    return !(*(uint32_t*)(uintptr_t)((uint64_t)uart_addr + UART_LSR_OFFSET) & UART_TXFF_MASK);
}

uint32_t pl011_put_char(const unsigned char *ch, uint32_t max_bytes)
{
    return put_debug_char_common(ch, is_pl011_ready, max_bytes, 0);
}
