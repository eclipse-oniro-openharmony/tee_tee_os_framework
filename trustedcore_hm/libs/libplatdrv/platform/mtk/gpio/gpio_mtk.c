/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: MTK GPIO driver Source file
 * Author: tangjianbo
 * Create: 2020-01-21
 */
#include "gpio_mtk.h"
#include "drv_module.h"
#include "sre_log.h"
#include <stdlib.h>
#include <stdio.h>
#include <sre_syscall.h>

#define GPIO_ERR(fmt, args...)  tloge("[gpio]"fmt, ##args)
#ifdef GPIO_DEBUG
#define GPIO_DBG(fmt, args...)  tloge("[gpio]"fmt, ##args)
#else
#define GPIO_DBG(fmt, args...)
#endif

/* base address, mapped form physical address */
unsigned char *g_gpio_171_mode_base_va = NULL;
unsigned char *g_gpio_171_dir_base_va = NULL;
unsigned char *g_gpio_171_data_out_base_va = NULL;

unsigned char *g_gpio_5_mode_base_va = NULL;
unsigned char *g_gpio_5_dir_base_va = NULL;
unsigned char *g_gpio_5_pull_up_base_va = NULL;
unsigned char *g_gpio_5_pull_down_base_va = NULL;

unsigned char *g_gpio_14_mode_base_va = NULL;
unsigned char *g_gpio_14_dir_base_va = NULL;
unsigned char *g_gpio_14_data_out_base_va = NULL;

unsigned char *g_gpio_15_mode_base_va = NULL;
unsigned char *g_gpio_15_dir_base_va = NULL;
unsigned char *g_gpio_15_pull_pupd_base_va = NULL;

unsigned char *g_gpio_47_mode_base_va = NULL;
unsigned char *g_gpio_47_dir_base_va = NULL;
unsigned char *g_gpio_47_data_out_base_va = NULL;

unsigned char *g_gpio_44_mode_base_va = NULL;
unsigned char *g_gpio_44_dir_base_va = NULL;
unsigned char *g_gpio_44_pull_up_base_va = NULL;
unsigned char *g_gpio_44_pull_down_base_va = NULL;

void set_gpio_171_data_out(uint32_t data)
{
    uint32_t value = 0;

    GPIO_DBG("Set GPIO171 data out:%u ", data);

    GPIO_READ(g_gpio_171_data_out_base_va, value);

    GPIO_WRITE(g_gpio_171_data_out_base_va, (value & (~GPIO171_DATAOUT_MASK)) | (data << GPIO171_DATAOUT_OFFSET));

    GPIO_READ(g_gpio_171_data_out_base_va, value);
    GPIO_DBG("now GPIO171 dataout:0x%x", value & GPIO171_DATAOUT_MASK);
}

void set_gpio_14_data_out(uint32_t data)
{
    uint32_t value = 0;

    GPIO_DBG("Set GPIO14 data out:%u ", data);

    GPIO_READ(g_gpio_14_data_out_base_va, value);

    GPIO_WRITE(g_gpio_14_data_out_base_va, (value & (~GPIO14_DATAOUT_MASK)) | (data << GPIO14_DATAOUT_OFFSET));

    GPIO_READ(g_gpio_14_data_out_base_va, value);
    GPIO_DBG("now GPIO14 dataout:0x%x", value & GPIO14_DATAOUT_MASK);
}

void set_gpio_47_data_out(uint32_t data)
{
    uint32_t value = 0;

    GPIO_DBG("Set GPIO47 data out:%u ", data);

    GPIO_READ(g_gpio_47_data_out_base_va, value);

    GPIO_WRITE(g_gpio_47_data_out_base_va, (value & (~GPIO47_DATAOUT_MASK)) | (data << GPIO47_DATAOUT_OFFSET));

    GPIO_READ(g_gpio_47_data_out_base_va, value);
    GPIO_DBG("now GPIO47 dataout:0x%x", value & GPIO47_DATAOUT_MASK);
}

void set_gpio_data_out(uint32_t mode_base_addr, uint32_t gpio_bit_offset, uint32_t data)
{
    uint32_t value = 0;
    uint32_t gpio_mask = 1 << gpio_bit_offset;

    GPIO_READ(mode_base_addr, value);

    GPIO_DBG("Set mode_base_addr:0x%X gpio_bit_offset:0x%X data out:%u",
        mode_base_addr, gpio_bit_offset, data);

    GPIO_WRITE(mode_base_addr, (value & (~gpio_mask)) | (data << gpio_bit_offset));

    GPIO_READ(mode_base_addr, value);
    GPIO_DBG("now GPIO data out:0x%x", value);
}

void set_gpio_5_pull(uint32_t up, uint32_t down)
{
    uint32_t value_up = 0;
    uint32_t value_down = 0;

    GPIO_DBG("Set GPIO5 pull up:%u down:%u", up, down);

    GPIO_READ(g_gpio_5_pull_up_base_va, value_up);
    GPIO_READ(g_gpio_5_pull_down_base_va, value_down);

    GPIO_WRITE(g_gpio_5_pull_up_base_va, (value_up & (~GPIO5_PULLUP_MASK)) | (up << GPIO5_PULLUP_OFFSET));
    GPIO_WRITE(g_gpio_5_pull_down_base_va, (value_down & (~GPIO5_PULLDOWN_MASK)) | (down << GPIO5_PULLDOWN_OFFSET));

    GPIO_READ(g_gpio_5_pull_up_base_va, value_up);
    GPIO_DBG("now GPIO5 pullup:0x%x", value_up & GPIO5_PULLUP_MASK);

    GPIO_READ(g_gpio_5_pull_down_base_va, value_down);
    GPIO_DBG("now GPIO5 pulldown:0x%x", value_down & GPIO5_PULLDOWN_MASK);
}

void set_gpio_15_pull(uint32_t up, uint32_t down)
{
    uint32_t value_pupd = 0;

    GPIO_DBG("Set GPIO15 pull up:%u down:%u", up, down);

    GPIO_READ(g_gpio_15_pull_pupd_base_va, value_pupd);

    if (down)
        GPIO_WRITE(g_gpio_15_pull_pupd_base_va,
            (value_pupd & (~GPIO15_PULLPUPD_MASK)) | (GPIO15_PULL_DOWN << GPIO15_PULLPUPD_OFFSET));
    else if (up)
        GPIO_WRITE(g_gpio_15_pull_pupd_base_va,
            (value_pupd & (~GPIO15_PULLPUPD_MASK)) | (GPIO15_PULL_UP << GPIO15_PULLPUPD_OFFSET));

    GPIO_READ(g_gpio_15_pull_pupd_base_va, value_pupd);
    GPIO_DBG("now GPIO15 pulldown:0x%x", value_pupd & GPIO15_PULLPUPD_MASK);
}

void set_gpio_44_pull(uint32_t up, uint32_t down)
{
    uint32_t value_up = 0;
    uint32_t value_down = 0;

    GPIO_DBG("Set GPIO44 pull up:%u down:%u", up, down);

    GPIO_READ(g_gpio_44_pull_up_base_va, value_up);
    GPIO_READ(g_gpio_44_pull_down_base_va, value_down);

    GPIO_WRITE(g_gpio_44_pull_up_base_va,
        (value_up & (~GPIO44_PULLUP_MASK)) | (up << GPIO44_PULLUP_OFFSET));
    GPIO_WRITE(g_gpio_44_pull_down_base_va,
        (value_down & (~GPIO44_PULLDOWN_MASK)) | (down << GPIO44_PULLDOWN_OFFSET));

    GPIO_READ(g_gpio_44_pull_up_base_va, value_up);
    GPIO_DBG("now GPIO44 pullup:0x%x", value_up & GPIO44_PULLUP_MASK);

    GPIO_READ(g_gpio_44_pull_down_base_va, value_down);
    GPIO_DBG("now GPIO44 pulldown:0x%x", value_down & GPIO44_PULLDOWN_MASK);
}

void gpio_map_register(void)
{
    g_gpio_171_data_out_base_va = (unsigned char *)GPIO171_DATAOUT;
    g_gpio_5_pull_up_base_va = (unsigned char *)GPIO5_PULLUP;
    g_gpio_5_pull_down_base_va = (unsigned char *)GPIO5_PULLDOWN;
    g_gpio_14_data_out_base_va = (unsigned char *)GPIO14_DATAOUT;
    g_gpio_15_pull_pupd_base_va = (unsigned char *)GPIO15_PULLPUPD;
    g_gpio_47_data_out_base_va = (unsigned char *)GPIO47_DATAOUT;
    g_gpio_44_pull_up_base_va = (unsigned char *)GPIO44_PULLUP;
    g_gpio_44_pull_down_base_va = (unsigned char *)GPIO44_PULLDOWN;
}

int gpio_init(void)
{
    gpio_map_register();
    return 0;
}

DECLARE_TC_DRV(
    gpio,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    gpio_init,
    NULL,
    NULL,
    NULL,
    NULL
);
