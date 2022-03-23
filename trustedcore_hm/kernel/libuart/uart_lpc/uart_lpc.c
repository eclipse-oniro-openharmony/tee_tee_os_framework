/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: uart output, hw adaptor, lpc uart
 * Create: 2021-07
 */
#include <uart_lpc.h>

#include <uart_register.h>

#define LPC_SERIAL_BASE     0x2F8

#define UART_SEND_DELAY      10000000u
#define BAUDRATE             115200

#define UART_THR_REG         (LPC_SERIAL_BASE + UART_THR)
#define UART_RBR_REG         (LPC_SERIAL_BASE + UART_RBR)
#define UART_DLL_REG         (LPC_SERIAL_BASE + UART_DLL)
#define UART_DLH_REG         (LPC_SERIAL_BASE + UART_DLH)
#define UART_IEL_REG         (LPC_SERIAL_BASE + UART_IEL)
#define UART_IIR_REG         (LPC_SERIAL_BASE + UART_IIR)
#define UART_FCR_REG         (LPC_SERIAL_BASE + UART_FCR)
#define UART_LCR_REG         (LPC_SERIAL_BASE + UART_LCR)
#define UART_LSR_REG         (LPC_SERIAL_BASE + UART_LSR)
#define UART_USR_REG         (LPC_SERIAL_BASE + UART_USR)

#define UART_RBR     0x00
#define UART_THR     0x00
#define UART_DLL     0x00
#define UART_DLH     0x01
#define UART_IEL     0x01
#define UART_IIR     0x02
#define UART_FCR     0x02
#define UART_LCR     0x03
#define UART_MCR     0x04
#define UART_LSR     0x05

/* register definitions */
#define UART_FCR_EN          0x01
#define UART_FCR_RXCLR       0x02
#define UART_FCR_TXCLR       0x04
#define UART_FCR_CLEARFIFO   0x00
#define UART_FCR_RXL1        0x00
#define UART_FCR_RXL4        0x40
#define UART_FCR_RXL8        0x80
#define UART_FCR_RXL14       0xc0
#define UART_FCR_TXL0        0x00
#define UART_FCR_TXL4        0x20
#define UART_FCR_TXL8        0x30
#define UART_FCR_TXL14       0x10

/* LCR ¡ñ Name: Line Control Register fields */
#define UART_LCR_DLAB   0x80     /* 0£­disable£»1£­enable */
#define UART_LCR_EPS    0x10     /* 0¡ª¡ªodd check, 1¡ª¡ªeven check */
#define UART_LCR_PEN    0x08     /* 0£­disable£»1£­enable parity check */
#define UART_LCR_STOP   0x04     /* 0¡ª¡ª1 stop bit;1¡ª¡ª1.5 or 2 stop bits */
#define UART_LCR_DLS8   0x03     /* 00¡ª¡ª5bit 01¡ª¡ª6bit 10¡ª¡ª7bit 11¡ª¡ª8bit data */
#define UART_LCR_DLS7   0x02     /* 00¡ª¡ª5bit 01¡ª¡ª6bit 10¡ª¡ª7bit 11¡ª¡ª8bit data */
#define UART_LCR_DLS6   0x01     /* 00¡ª¡ª5bit 01¡ª¡ª6bit 10¡ª¡ª7bit 11¡ª¡ª8bit data */
#define UART_LCR_DLS5   0x00     /* 00¡ª¡ª5bit 01¡ª¡ª6bit 10¡ª¡ª7bit 11¡ª¡ª8bit data */

#define LPC_BASE                0
#define LPC_START_REG           (LPC_BASE + 0x00)
#define LPC_OP_STATUS_REG       (LPC_BASE + 0x04)
#define LPC_IRQ_ST_REG          (LPC_BASE + 0x08)
#define LPC_OP_LEN_REG          (LPC_BASE + 0x10)
#define LPC_CMD_REG             (LPC_BASE + 0x14)
#define LPC_FWH_ID_MSIZE_REG    (LPC_BASE + 0x18)
#define LPC_ADDR_REG            (LPC_BASE + 0x20)
#define LPC_WDATA_REG           (LPC_BASE + 0x24)
#define LPC_RDATA_REG           (LPC_BASE + 0x28)
#define LPC_LONG_CNT_REG        (LPC_BASE + 0x30)
#define LPC_TX_FIFO_ST_REG      (LPC_BASE + 0x50)
#define LPC_RX_FIFO_ST_REG      (LPC_BASE + 0x54)
#define LPC_TIME_OUT_REG        (LPC_BASE + 0x58)
#define LPC_SIRQ_CTRL0_REG      (LPC_BASE + 0x80)
#define LPC_SIRQ_CTRL1_REG      (LPC_BASE + 0x84)
#define LPC_SIRQ_INT_REG        (LPC_BASE + 0x90)
#define LPC_SIRQ_INT_MASK_REG   (LPC_BASE + 0x94)
#define LPC_SIRQ_STAT_REG       (LPC_BASE + 0xA0)

#define LPC_FIFO_LEN            (16)

#define LPC_OP_STATUS_REG_MASK  0x2u
#define LPC_IRQ_ST_REG_MASK     0x2u
#define TIMEOUT_COUNT_MAX       100000u

enum LPC_ADDR_MODE {
    LPC_ADDR_MODE_INCREASE,
    LPC_ADDR_MODE_SINGLE
};

enum LPC_TYPE {
    LPC_TYPE_IO,
    LPC_TYPE_MEM,
    LPC_TYPE_FWH
};

union LPC_CMD_STRUCT {
    struct {
        unsigned int lpc_wr : 1;
        unsigned int lpc_type : 2;
        unsigned int same_addr : 1;
        unsigned int resv : 28;
    } bits;

    unsigned int u32;
};

static inline void mmio_write_32(uintptr_t addr, uint32_t value)
{
    *(volatile uint32_t*)addr = value;
}

static inline uint32_t mmio_read_32(uintptr_t addr)
{
    return *(volatile uint32_t*)addr;
}

static int lpc_byte_write(unsigned int addr,
                          unsigned char data, uintptr_t uart)
{
    union LPC_CMD_STRUCT  lpc_cmd = { .u32 = 0 };
    unsigned int cnt = 0;

    lpc_cmd.bits.lpc_wr = 1;
    lpc_cmd.bits.lpc_type = LPC_TYPE_IO;
    lpc_cmd.bits.same_addr = LPC_ADDR_MODE_SINGLE;

    mmio_write_32((uintptr_t)(LPC_CMD_REG + (uint64_t)uart), lpc_cmd.u32);
    mmio_write_32((uintptr_t)(LPC_OP_LEN_REG + (uint64_t)uart), 1);
    mmio_write_32((uintptr_t)(LPC_WDATA_REG + (uint64_t)uart), data);
    mmio_write_32((uintptr_t)(LPC_ADDR_REG + (uint64_t)uart), addr);
    mmio_write_32((uintptr_t)(LPC_START_REG + (uint64_t)uart), 1);

    while (!(mmio_read_32((uintptr_t)(LPC_IRQ_ST_REG + (uint64_t)uart)) & LPC_IRQ_ST_REG_MASK)) {
        if (cnt > TIMEOUT_COUNT_MAX)
            return -1;
        cnt++;
    }

    mmio_write_32((uintptr_t)(LPC_IRQ_ST_REG + (uint64_t)uart), LPC_IRQ_ST_REG_MASK);

    if (mmio_read_32((uintptr_t)(LPC_OP_STATUS_REG + (uint64_t)uart)) & LPC_OP_STATUS_REG_MASK)
        return 0;

    return -1;
}

static int lpc_byte_read(unsigned int addr,
                         unsigned char *data, uintptr_t uart)
{
    unsigned int cnt = 0;
    union LPC_CMD_STRUCT lpc_cmd = { .u32 = 0 };

    lpc_cmd.bits.lpc_wr = 0;
    lpc_cmd.bits.lpc_type = LPC_TYPE_IO;
    lpc_cmd.bits.same_addr = LPC_ADDR_MODE_SINGLE;
    mmio_write_32((uintptr_t)(LPC_CMD_REG + (uint64_t)uart), lpc_cmd.u32);

    mmio_write_32((uintptr_t)(LPC_OP_LEN_REG + (uint64_t)uart), 1);
    mmio_write_32((uintptr_t)(LPC_ADDR_REG + (uint64_t)uart), addr);

    mmio_write_32((uintptr_t)(LPC_START_REG + (uint64_t)uart), 1);

    while (!(mmio_read_32((uintptr_t)(LPC_IRQ_ST_REG + (uint64_t)uart)) & LPC_IRQ_ST_REG_MASK)) {
        if (cnt > TIMEOUT_COUNT_MAX)
            return -1;

        cnt++;
    }

    mmio_write_32((uintptr_t)(LPC_IRQ_ST_REG + (uint64_t)uart), LPC_IRQ_ST_REG_MASK);

    if (mmio_read_32((uintptr_t)(LPC_OP_STATUS_REG + (uint64_t)uart)) & LPC_OP_STATUS_REG_MASK) {
        *data = mmio_read_32((uintptr_t)(LPC_RDATA_REG + (uint64_t)uart));
        return 0;
    }

    return -1;
}

static int console_core_putc(unsigned long base_addr, unsigned char ch, uintptr_t uart)
{
    unsigned int ul_loop = 0;
    unsigned char temp = 0;

    while (ul_loop < UART_SEND_DELAY) {
        (void)lpc_byte_read(base_addr + UART_LSR, &temp, uart);
        if ((temp & 0x40) == 0x40)
            break;

        ul_loop++;
    }

    (void)lpc_byte_write(base_addr + UART_THR, ch, uart);

    ul_loop = 0;
    while (ul_loop < UART_SEND_DELAY) {
        (void)lpc_byte_read(base_addr + UART_LSR, &temp, uart);
        if ((temp & 0x40) == 0x40)
            break;

        ul_loop++;
    }

    return 0;
}

uint32_t uart_lpc_put_char(const unsigned char *ch, uint32_t max_bytes)
{
    (void)max_bytes;
    if (ch == NULL)
        return 0;

    uintptr_t uart_addr = get_uart_addr();

    if (*ch == 0x0A)
        (void)console_core_putc(LPC_SERIAL_BASE, '\r', uart_addr);

    (void)console_core_putc(LPC_SERIAL_BASE, *ch, uart_addr);
    return 1;
}
