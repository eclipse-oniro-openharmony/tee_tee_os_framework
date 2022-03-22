/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: TUI tp platform common driver
 * Author: chenpuwang
 * Create: 2020-09-21
 */
#ifndef _PLATFORM_TOUCHSCREEN_
#define _PLATFORM_TOUCHSCREEN_

#include "tui_drv_types.h"
#include "../drv_pal/include/drv_fwk.h"
#include "../spi/inc/spi.h"


#define SPI_BUF_MAX_SIZE 4096
/* mtk irq type */
#define EINTF_TRIGGER_LEVEL_LOW 0x00000000
#define EINTF_TRIGGER_LEVEL_HIGH 0x00000001
#define EINTF_TRIGGER_LEVEL_FALLING 0x00000002
#define EINTF_TRIGGER_LEVEL_RISING 0x00000003

enum DEVAPC_MODULE_REQ_TYPE {
     DEVAPC_MODULE_REQ_CAMERA_ISP = 0,
     DEVAPC_MODULE_REQ_IMGSENSOR,
     DEVAPC_MODULE_REQ_VDEC,
     DEVAPC_MODULE_REQ_VENC,
     DEVAPC_MODULE_REQ_M4U,
     DEVAPC_MODULE_REQ_I2C,
     DEVAPC_MODULE_REQ_SPI,
     DEVAPC_MODULE_REQ_DISP,
     DEVAPC_MODULE_REQ_NUM,
};

/* bsp interface */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6885)
#define MTK_SIP_TEE_SEC_DEINT_CONFIGURE_AARCH32 0x8200020C
#define MTK_SIP_TEE_SEC_DEINT_RELEASE_AARCH32 0x8200020D

#define MTK_SIP_TEE_SEC_DEINT_ACK_AARCH32 0x8200020E
#define MTK_SIP_TEE_SEC_DEINT_ACK_AARCH64 0xC200020E

#endif
int32_t tp_enter_secure_os_config(void);
void tp_exit_secure_os_config(void);

/* irq */
void tui_tp_clear_irq(void);
uint32_t tui_tp_get_cur_irq_num(void);
uint32_t tui_tp_get_cur_irq_flags(int type);
void tui_tp_irq_conctrl(int enable);
int32_t tui_tp_irq_request(uint32_t irq_num, void (*handler)(void *),
    uint32_t irqflags, void *data);

/* gpio */
uint32_t tui_tp_get_cur_gpio_num(void);
uint32_t tui_tp_get_gpio_value(uint32_t gpio_num);

/* bus */
int32_t ts_spi_sync(uint16_t size, uint8_t *txbuf, uint8_t *rxbuf);

#endif
