/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: common func for tzasc
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#include "tee_drv_tzasc_common.h"

unsigned int tzasc_get_bit(unsigned long long addr, unsigned int shift)
{
    return tzasc_read_bits(addr, shift, 1);
}

void tzasc_set_bit(unsigned long long addr, unsigned int shift)
{
    tzasc_write_bits(addr, 1, shift, 1);
}

void tzasc_clear_bit(unsigned long long addr, unsigned int shift)
{
    tzasc_write_bits(addr, 0, shift, 1);
}

void tzasc_dump_addr(const char *name, char *addr, unsigned int size)
{
    char *p = NULL;

    if (addr == NULL || size == 0) {
        tzasc_error("Invalid input\n");
        return;
    }

    if (name != NULL) {
        tzasc_printf("------------------[%s]---------------------\n", name);
    }

    p = addr;
    while (p < (addr + size)) {
        if (!((p - addr) % 16) && (p - addr) != 0) { /* 4reg one line, 4byte one reg; 4*4 is 16 */
            tzasc_printf("\n");
            tzasc_printf("0x%x: %08x ", (unsigned int)(uintptr_t)p, tzasc_read((unsigned int)(uintptr_t)p));
        } else if ((p - addr) == 0) {
            tzasc_printf("0x%x: %08x ", (unsigned int)(uintptr_t)p, tzasc_read((unsigned int)(uintptr_t)p));
        } else {
            tzasc_printf("%08x ", tzasc_read((unsigned int)(uintptr_t)p));
        }

        p += 4; /* 4 byte per reg */
    }

    tzasc_printf("\n");
}

/* random number < 0x4000, delay about 500us */
void tzasc_random_delay(void)
{
    unsigned int loop = 0xffffffff;

    if (hi_tee_drv_hal_rng_generate(&loop, sizeof(loop))) {
        tzasc_sys_reset();
    }

    loop = loop & 0x3fff;
    while (loop--) {
        asm("nop");
    }
}

void tzasc_sys_reset(void)
{
    tzasc_error("tzasc error, reset now\n");
    hi_tee_drv_hal_sys_reset();
}

int tzasc_request_irq(unsigned int irq, void *handler, const void *arg)
{
    return hi_tee_drv_hal_request_irq(irq, handler, 0, arg);
}

void tzasc_unregister_irq(unsigned int irq)
{
    hi_tee_drv_hal_unregister_irq(irq);
}

/* for security */
void tzasc_sec_write(unsigned int value, unsigned int addr)
{
    volatile unsigned int check_value;

    tzasc_write(value, addr);
    check_value = tzasc_read(addr);
    if (value != check_value) {
        tzasc_error("Fail to set 0x%X(0x%X) to 0x%X\n", addr, check_value, value);
        tzasc_sys_reset();
    }
    tzasc_random_delay();
    check_value = tzasc_read(addr);
    check_value = ~check_value;
    if (~value != check_value) {
        tzasc_error("Fail to set 0x%X(~0x%X) to 0x%X\n", addr, check_value, value);
        tzasc_sys_reset();
    }
    tzasc_random_delay();
    check_value = tzasc_read(addr);
    if (value != check_value) {
        tzasc_error("Fail to set 0x%X(0x%X) to 0x%X\n", addr, check_value, value);
        tzasc_sys_reset();
    }
}

