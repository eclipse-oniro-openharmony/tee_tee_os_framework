/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: MTK GPIO Define Header File
 * Author: tangjianbo
 * Create: 2020-01-21
 */
#ifndef GPIO_MTK_H
#define GPIO_MTK_H

typedef unsigned int uint32_t;
typedef signed int int32_t;
typedef unsigned char uint8_t;

/* GPIO171 & GPIO5   base address (physical address) */
#define GPIO171_MODE            (0x10005000 + 0x450)
#define GPIO171_DIR             (0x10005000 + 0x50)
#define GPIO171_DATAOUT         (0x10005000 + 0x150)

#define GPIO5_MODE              (0x10005000 + 0x300)
#define GPIO5_DIR               (0x10005000 + 0x0)
#define GPIO5_PULLUP            (0x10002800 + 0x60)
#define GPIO5_PULLDOWN          (0x10002800 + 0x40)

#define GPIO171_MODE_OFFSET     12
#define GPIO171_DIR_OFFSET      11
#define GPIO171_DATAOUT_OFFSET  11

#define GPIO171_MODE_MASK       0xf000
#define GPIO171_DIR_MASK        0x800
#define GPIO171_DATAOUT_MASK    0x800

#define GPIO5_MODE_OFFSET       20
#define GPIO5_DIR_OFFSET        5
#define GPIO5_PULLUP_OFFSET     13
#define GPIO5_PULLDOWN_OFFSET   13

#define GPIO5_MODE_MASK         0x10000
#define GPIO5_DIR_MASK          0x20
#define GPIO5_PULLUP_MASK       0x2000
#define GPIO5_PULLDOWN_MASK     0x2000

/* GPIO14 & GPIO15   base address (physical address) */
#define GPIO14_MODE             (0x10005000 + 0x310)
#define GPIO14_DIR              (0x10005000 + 0x00)
#define GPIO14_DATAOUT          (0x10005000 + 0x100)

#define GPIO15_MODE             (0x10005000 + 0x310)
#define GPIO15_DIR              (0x10005000 + 0x00)
#define GPIO15_PULLPUPD         (0x11E70000 + 0x20)

#define GPIO14_MODE_OFFSET      24
#define GPIO14_DIR_OFFSET       14
#define GPIO14_DATAOUT_OFFSET   14

#define GPIO14_MODE_MASK        0x0f000000
#define GPIO14_DIR_MASK         0x4000
#define GPIO14_DATAOUT_MASK     0x4000

#define GPIO15_MODE_OFFSET      28
#define GPIO15_DIR_OFFSET       15
#define GPIO15_PULLPUPD_OFFSET  5

#define GPIO15_MODE_MASK        0xf0000000
#define GPIO15_DIR_MASK         0x8000
#define GPIO15_PULLPUPD_MASK    0x20

/* GPIO44 & GPIO47 base address (physical address) */
#define GPIO44_PULLUP           (0x11D10000 + 0x90)
#define GPIO44_PULLDOWN         (0x11D10000 + 0x60)
#define GPIO44_PULLUP_OFFSET    0
#define GPIO44_PULLDOWN_OFFSET  0
#define GPIO44_PULLUP_MASK      0x1
#define GPIO44_PULLDOWN_MASK    0x1

#define GPIO47_MODE             (0x10005000 + 0x350)
#define GPIO47_DIR              (0x10005000 + 0x10)
#define GPIO47_DATAOUT          (0x10005000 + 0x110)
#define GPIO47_MODE_OFFSET      28
#define GPIO47_DIR_OFFSET       15
#define GPIO47_DATAOUT_OFFSET   15
#define GPIO47_MODE_MASK        0x70000000
#define GPIO47_DIR_MASK         0x8000
#define GPIO47_DATAOUT_MASK     0x8000

#define GPIO_MODE               0
#define DIR_IN                  0
#define DIR_OUT                 1
#define DATAOUT_LOW             0
#define DATAOUT_HIGH            1
#define PULL_ENABLE             1
#define PULL_DISABLE            0

#define GPIO15_PULL_UP          0
#define GPIO15_PULL_DOWN        1

/*
 * READ/WRITE  register  API
 * we don't recommend  to  hard code set any register in tee ,
 * it may lead to issue difficult to debug, and difficult to porting
 */
#define gpio_reg_get_32(addr, ret) do {       \
    __asm__ volatile ("isb");                 \
    __asm__ volatile ("dsb sy");              \
    (ret) = *(volatile unsigned int *)(addr); \
    __asm__ volatile ("isb");                 \
    __asm__ volatile ("dsb sy");              \
} while (0)

#define gpio_reg_set_32(addr, val) do {       \
    __asm__ volatile ("isb");                 \
    __asm__ volatile ("dsb sy");              \
    *(volatile unsigned int *)(addr) = (val); \
    __asm__ volatile ("isb");                 \
    __asm__ volatile ("dsb sy");              \
} while (0)

#define GPIO_READ(addr, ret)  gpio_reg_get_32(addr, ret)
#define GPIO_WRITE(addr, val) gpio_reg_set_32(addr, val)

void set_gpio_171_data_out(uint32_t data);
void set_gpio_14_data_out(uint32_t data);
void set_gpio_47_data_out(uint32_t data);
void set_gpio_5_pull(uint32_t up, uint32_t down);
void set_gpio_15_pull(uint32_t up, uint32_t down);
void set_gpio_44_pull(uint32_t up, uint32_t down);

#endif
