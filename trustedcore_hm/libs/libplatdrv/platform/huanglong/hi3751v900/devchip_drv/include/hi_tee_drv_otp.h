/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:OTP drvier level head file.
 * Author: Linux SDK team
 * Create: 2019/06/20
 */

#ifndef __HI_TEE_DRV_OTP_H__
#define __HI_TEE_DRV_OTP_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

hi_s32 hi_drv_otp_init(hi_void);
hi_s32 hi_drv_otp_deinit(hi_void);
hi_s32 hi_drv_otp_reset(hi_void);
hi_s32 hi_drv_otp_read(hi_u32 addr, hi_u32 *value);
hi_s32 hi_drv_otp_read_byte(hi_u32 addr, hi_u8 *value);
hi_s32 hi_drv_otp_read_bits_onebyte(hi_u32 addr, hi_u32 start_bit, hi_u32 bit_width, hi_u8 *value);
hi_s32 hi_drv_otp_write(hi_u32 addr, hi_u32 value);
hi_s32 hi_drv_otp_write_byte(hi_u32 addr, hi_u8 value);
hi_s32 hi_drv_otp_write_bit(hi_u32 addr, hi_u32 bit_pos);
hi_s32 hi_drv_otp_write_bits_onebyte(hi_u32 addr, hi_u32 start_bit, hi_u32 bit_width, hi_u8 value);

hi_s32 otp_drv_mod_init(hi_void);

hi_s32 hi_otp_secureos_version_get(hi_u32 *version);
hi_s32 hi_otp_secureos_version_set(hi_u32 version);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __HI_DRV_OTP_H__ */

