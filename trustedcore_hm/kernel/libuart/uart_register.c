/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: uart output, hw adaptor
 * Create: 2021-07
 */
#include <uart_register.h>

#include <config.h>
#include <plat_cfg_public.h>

#include <pl011.h>
#include <pl011_general.h>
#include <pl011_v500.h>
#include <uart_lpc.h>

#define ERR 0xffffffff
#define ONE_BYTES 1

#define INVALID_UART 0x0
static uintptr_t g_uart_addr = 0;
static UART_PUT_CHAR g_put_char_handler = NULL;
static bool g_uart_output_enable = true;

/*
* REVIEW CHECKLIST
* ARG: caller should guarantee the validity of parameters
* RIGHTS: N/A
* BUFOVF: N/A
* LOG: N/A
* RET: N/A
* RACING: N/A
* LEAK: N/A
* ARITHOVF: N/A
*/
struct uart_ops {
    uint64_t uart_type;
    UART_PUT_CHAR put_char_handler;
};

static struct uart_ops g_uart_ops[] = {
    { PL011_TYPE, pl011_put_char },

    { PL011_GENERAL_TYPE, pl011_general_put_char },

    { PL011_V500_TYPE, uart_v500_put_char },

    { UART_LPC_TYPE, uart_lpc_put_char },
};

void set_uart_addr(uint64_t uart_addr)
{
    g_uart_addr = (uintptr_t)uart_addr;
}

uintptr_t get_uart_addr(void)
{
    return g_uart_addr;
}

void ctrl_uart_output(bool enable)
{
    g_uart_output_enable = enable;
}

void register_uart(uint64_t uart_type)
{
    uint32_t i;

    if (((uart_type >> UART_TYPE_MASK) << UART_TYPE_MASK) != UART_ENABLE_FLAG)
        return;

    for (i = 0; i < (uint32_t)(sizeof(g_uart_ops) / sizeof(struct uart_ops)); i++) {
        if (g_uart_ops[i].uart_type == (uart_type & 0xFFFFFFFF)) {
            g_put_char_handler = g_uart_ops[i].put_char_handler;
            break;
        }
    }
}

void put_debug_char(unsigned char ch)
{
    if (!g_uart_output_enable)
        return;

    if (g_put_char_handler != NULL)
        while (g_put_char_handler(&ch, ONE_BYTES) == 0);
}

uint32_t put_debug_char_common(const unsigned char *ch, IS_UART_READY is_uart_ready,
                               uint32_t max_bytes, uint32_t data_offset)
{
    if (ch == NULL || g_uart_addr == 0 || is_uart_ready == NULL)
        return 0;

    uint32_t remaining = max_bytes;
    while (remaining > 0 && is_uart_ready(g_uart_addr) != 0 && *ch != '\0') {
        ((struct uart_data*)(g_uart_addr + data_offset))->data_reg = *ch;
        ch++;
        remaining--;
    }

    return max_bytes - remaining;
}
