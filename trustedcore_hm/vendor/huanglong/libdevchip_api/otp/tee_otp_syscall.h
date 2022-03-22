/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Defines the interface for calling the OTP read/write method.
 * Author: Hisilicon hisecurity team
 * Create: 2019-07-23
 */
#ifndef __TEE_OTP_SYSCALL_H__
#define __TEE_OTP_SYSCALL_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

hi_s32 otp_syscall_read(hi_u32 addr, hi_u32 *value);

hi_s32 otp_syscall_read_byte(hi_u32 addr, hi_u8 *value);

hi_s32 otp_syscall_write(hi_u32 addr, hi_u32 value);

hi_s32 otp_syscall_write_byte(hi_u32 addr, hi_u8 value);

hi_s32 otp_syscall_read_bits_one_byte(hi_u32 addr, hi_u8 start_bit, hi_u8 bit_width, hi_u8 *value);

hi_s32 otp_syscall_write_bits_one_byte(hi_u32 addr, hi_u8 start_bit, hi_u8 bit_width, hi_u8 value);

hi_s32 otp_syscall_write_bit(hi_u32 addr, hi_u8 bit_pos, hi_u8 bit_value);

hi_s32 otp_syscall_reset(hi_void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __TEE_OTP_SYSCALL_H__ */
