/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: uart output, hw adaptor
 * Create: 2020-12
 */

#ifndef LIBUART_UART_REGISTER_H
#define LIBUART_UART_REGISTER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define PL011_TYPE         0x101
#define PL011_GENERAL_TYPE 0x102
#define PL011_V500_TYPE    0x103
#define UART_LPC_TYPE      0x201
#define UART_INVALID_TYPE  0xFFFF

#define UART_TYPE_MASK     (32U)
#define UART_ENABLE_FLAG   ((uint64_t)(0x54524155U) << UART_TYPE_MASK)
#define UART_DISABLE_FLAG  ((uint64_t)(0x1234U) << UART_TYPE_MASK)

typedef uint32_t (*UART_PUT_CHAR)(const unsigned char *ch, uint32_t max_bytes);
typedef uint32_t (*IS_UART_READY)(uintptr_t uart_addr);

struct uart_data {
    uint32_t data_reg;
};

void set_uart_addr(uint64_t uart_addr);

uintptr_t get_uart_addr(void);

void ctrl_uart_output(bool enable);

void register_uart(uint64_t uart_type);

void put_debug_char(unsigned char ch);

uint32_t put_debug_char_common(const unsigned char *ch, IS_UART_READY is_uart_ready,
                               uint32_t max_bytes, uint32_t data_offset);

static inline void udelay(int n)
{
    while (n--) {
        __asm__ volatile("nop");
        __asm__ volatile("dsb sy");
    }
}

#endif
