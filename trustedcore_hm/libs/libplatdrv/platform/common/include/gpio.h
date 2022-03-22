/*
 * FileName: gpio.h
 * Description: define GPIO macros used for GPIO functions.
 * Copyright (C) Hisilicon technologies Co., Ltd All rights reserved.
 * Revision history:
 */
#ifndef _GPIO_H_
#define _GPIO_H_

#define GPIO_INVALID_VALUE_DIRECT (0xFFFFFFFF)
enum gpiomux_init_mode {
	GPIOMUX_M0 = 0,
	GPIOMUX_M1,
	GPIOMUX_M2,
	GPIOMUX_M3,
	GPIOMUX_M4,
	GPIOMUX_M5,
	GPIOMUX_M6,
	GPIOMUX_M7,
};

enum gpiomux_pull_type {
	GPIOMUX_NOPULL = 0,
	GPIOMUX_PULL_UP,
	GPIOMUX_PULL_DOWN,
};

enum gpiomux_direction {
	GPIOMUX_IN = 0,
	GPIOMUX_OUT,
};

enum gpiomux_output_value {
	GPIOMUX_LOW = 0,
	GPIOMUX_HIGH,
};

enum { IRQ_TYPE_NONE = 0,
	IRQ_TYPE_EDGE_RISING,
	IRQ_TYPE_EDGE_FALLING,
	IRQ_TYPE_EDGE_BOTH,
	IRQ_TYPE_LEVEL_HIGH,
	IRQ_TYPE_LEVEL_LOW,
	IRQ_TYPE_UNKNOWN,
};

extern int gpio_set_sec(unsigned int gpio_id);
extern void gpio_set_unsec(unsigned int gpio_id);
extern void gpio_set_direction_input(unsigned int gpio_id);
extern void gpio_set_direction_output(unsigned int gpio_id);
extern unsigned int gpio_get_direction(unsigned int gpio_id);
extern void gpio_set_value(unsigned int gpio_id, unsigned int expect_value);
extern unsigned int gpio_get_value(unsigned int gpio_id);
extern void gpio_set_mode(unsigned int gpio_id, unsigned int expect_value);
extern int gpio_irq_request(unsigned int gpio_id, void (*handler)(void *),
	unsigned int irqflags, void *data);
extern void gpio_free_irq(unsigned int gpio);
extern void gpio_irq_ctrl(unsigned int gpio_id, unsigned int enable);

static inline void gpio_irq_enable(unsigned int gpio_id)
{
	gpio_irq_ctrl(gpio_id, 1);
}

static inline void gpio_irq_disable(unsigned int gpio_id)
{
	gpio_irq_ctrl(gpio_id, 0);
}

#endif
