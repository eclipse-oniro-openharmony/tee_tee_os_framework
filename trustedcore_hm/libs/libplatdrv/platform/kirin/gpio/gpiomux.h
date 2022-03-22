#ifndef _GPIOMUX_H
#define _GPIOMUX_H

#define NO_IOMG 0xFFFFFFFF

#define GPIO_TO_GROUP(gpio) ((gpio) >> 3)

typedef struct {
	unsigned int gpio_id;
	unsigned int iocg_id;
	unsigned int iomg_id;
} gpio_io_info;

#endif
