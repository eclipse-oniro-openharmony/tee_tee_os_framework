/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: parade driver
 * Author: lijie
 * Create: 2017-04-02
 */
#ifndef _HISI_TUI_PANEL_
#define _HISI_TUI_PANEL_

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define I2C_NOVA_FW_ADDR 0x01 /* nova-data slave addr */
#define I2C_NOVA_HW_ADDR 0x62 /* nova-ctrl slave addr */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#define I2C_PARADE_ADDR 0x1C /* parade-salve addr */
#else
#define I2C_PARADE_ADDR 0x24 /* parade-salve addr */
#endif
#define I2C_FTS_ADDR 0x38
#define I2C_GT1X_ADDR 0x14
#define I2C_GTX8_ADDR 0x5d
#define TOUCH_MAX_FINGER_NUM 10
#define PAR_REG_BASE 0x00
#define FINGER_ENTER 0x01
#define FINGER_MOVING 0x02
#define GLOVE_TOUCH 0x06
#define HID_TOUCH_REPORT_ID 0x1
#define PARADE_TOUCH_REPORT_FRAME_OFFSET 7
#define PARADE_TOUCH_REPORT_MAX_SIZE 108 /* 7+ Number of Records(10) * Record Length(10)+1 */


/* chip packet offset */
#define MASK_SHORT 0xFFFF
#define MASK_CHAR 0x3
#define OFFSET_BYTE1 1
#define OFFSET_BYTE2 2
#define OFFSET_BYTE3 3
#define OFFSET_BYTE4 4
#define OFFSET_BYTE5 5
#define OFFSET_BYTE6 6
#define OFFSET_BYTE7 7
#define OFFSET_BYTE8 8
#define OFFSET_BYTE9 9

// print func
extern void uart_printf_func(const char *fmt, ...);

#ifdef TP_DEBUG
#define TP_LOG_DEBUG(fmt, args...) uart_printf_func(fmt, ##args)
#else
#define TP_LOG_DEBUG(fmt, args...)
#endif
#define TP_LOG_ERR(fmt, args...) uart_printf_func(fmt, ##args)
#define TP_LOG_INFO(fmt, args...) uart_printf_func(fmt, ##args)

int synaptics_device_init(void);
void tui_synaptics_exit(void);
int syna_tcm_device_init(void);
void tui_syna_tcm_exit(void);
int atmel_device_init(void);
void tui_atmel_exit(void);
int st_device_init(void);
void tui_st_exit(void);
int st_device_init_new(void);
void tui_st_exit_new(void);
int novatek_device_init(void);
int novatek_device_init_spi(void);
int parade_device_init(void);
int ts_jdi_init(void);
int sec_device_init(void);
int fts_device_init(void);
int gt1x_device_init(void);
int gtx8_device_init(void);
int elan_device_init(void);

int ts_tui_i2c_read(unsigned char *buf, unsigned short len, unsigned int slave_addr);
int ts_tui_i2c_read_directly(unsigned char *buf, unsigned short len, unsigned int slave_addr);
int ts_tui_i2c_read_reg16(unsigned char *buf, unsigned short len, unsigned int slave_addr);
int ts_tui_i2c_write(unsigned char *buf, unsigned short len, unsigned int slave_addr);
int ts_spi_sync(unsigned short size, unsigned char *txbuf, unsigned char *rxbuf);
#endif
