/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definitions of common functions, enumeration, and structures
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-01-20
 */
#ifndef __TEE_HAL_HDMIRX_COMM_H__
#define __TEE_HAL_HDMIRX_COMM_H__

#include "hi_type_dev.h"
#include "tee_drv_hdmirx_struct.h"

#define BIT0   0x01
#define BIT1   0x02
#define BIT2   0x04
#define BIT3   0x08
#define BIT4   0x10
#define BIT5   0x20
#define BIT6   0x40
#define BIT7   0x80
#define BIT7_5 (BIT7 | BIT6 | BIT5)
#define BIT7_6 (BIT7 | BIT6)
#define BIT5_4 (BIT5 | BIT4)
#define BIT4_3 (BIT4 | BIT3)
#define BIT4_2 (BIT4 | BIT3 | BIT2)
#define BIT3_2 (BIT3 | BIT2)
#define BIT2_1 (BIT2 | BIT1)

#define BIT7_4 (BIT7 | BIT6 | BIT5 | BIT4)
#define BIT6_3 (BIT6 | BIT5 | BIT4 | BIT3)
#define BIT6_4 (BIT6 | BIT5 | BIT4)
#define BIT6_2 (BIT6 | BIT5 | BIT4 | BIT3 | BIT2)
#define BIT1_0 (BIT1 | BIT0)
#define BIT2_0 (BIT2 | BIT1 | BIT0)
#define BIT3_0 (BIT3 | BIT2 | BIT1 | BIT0)
#define BIT3_1 (BIT3 | BIT2 | BIT1)
#define BIT4_0 (BIT0 | BIT1 | BIT2 | BIT3 | BIT4)
#define BIT4_1 (BIT1 | BIT2 | BIT3 | BIT4)
#define BIT5_0 (BIT0 | BIT1 | BIT2 | BIT3 | BIT4 | BIT5)
#define BIT5_3 (BIT3 | BIT4 | BIT5)
#define BIT6_0 (BIT0 | BIT1 | BIT2 | BIT3 | BIT4 | BIT5 | BIT6)
#define BIT7_0 (BIT7 | BIT6 | BIT5 | BIT4 | BIT3 | BIT2 | BIT1 | BIT0)
#define BIT31_0 0xffffffff

#define reg_read(addr)  (*(volatile unsigned int *)(uintptr_t)(addr))
#define reg_write(addr, value)  (*(volatile unsigned int *)(uintptr_t)(addr) = (value))

hi_void hdmirx_hal_reg_init(hi_void);
hi_void hdmirx_hal_reg_deinit(hi_void);
hi_u32 hdmirx_hal_reg_read(hi_tee_drv_hdmirx_port port, hi_u32 addr);
hi_void hdmirx_hal_reg_write(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 value);
hi_u32 hdmirx_hal_reg_read_fld_align(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 mask);
hi_void hdmirx_hal_reg_write_fld_align(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 mask, hi_u32 value);
hi_void hdmirx_hal_reg_read_block(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 *dst, hi_u32 num);
hi_void hdmirx_hal_reg_set_bits(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 mask, hi_bool value);
hi_void hdmirx_hal_reg_write_block(hi_tee_drv_hdmirx_port port, hi_u32 addr, hi_u32 *src, hi_u32 num);
hi_u32 hdmirx_hal_crg_reg_read(hi_u32 offset);
hi_void hdmirx_hal_crg_write_fld_align(hi_u32 addr, hi_u32 mask, hi_u32 value);
hi_u32 hdmirx_hal_sys_ctrl_read_fld_align(hi_u32 addr, hi_u32 mask);

#endif /* __TEE_HAL_HDMIRX_COMM_H__ */
