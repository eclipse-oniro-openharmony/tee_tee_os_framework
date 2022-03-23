/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: The file defines the interfaces of otp drive.
 * Author: Hisilicon hisecurity group
 * Create: 2019-12-06
 */

#ifndef __TEE_OTP_FUNC_H__
#define __TEE_OTP_FUNC_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define BYTES_PER_UINT 4
#define UINT_STEP      8
#define BITS_PER_CHAR  8
#define BITS_PER_SHORT 16
#define BITS_PER_LONG  32
#define KEY_LEN        16
#define LOCK_LONGDATA_NUM 16
/*
* gen_mask_rev(05, 00)=0xffffffc0 gen_mask(05, 00)=0x0000003f
* gen_mask_rev(31, 05)=0x0000001f gen_mask(31, 05)=0xffffffe0
* gen_mask_rev(00, 01)=0xffffffff gen_mask(00, 01)=0x00000000
*/
#define gen_mask(h, l) \
    (((~0U) << (l)) & (~0U >> (BITS_PER_LONG - 1 - (h))))
#define gen_mask_rev(h, l) \
    ~(((~0U) << (l)) & (~0U >> (BITS_PER_LONG - 1 - (h))))

/*
* Note start_bit less than 8.
*/
#define bits_pos_2_byte_num(start_bit, bit_width) (hi_u32)(((start_bit) + (bit_width) + 0x7) / 0x8)


#define bits_2_byte_num(bit_width) (hi_u32)(((bit_width) + 0x7) / 0x8)

/*
* all the bits within one byte.
*/
#define bits_in_one_byte(start_bit, bit_width) ((start_bit) + (bit_width) <= 0x8)

typedef enum {
    HI_OTP_UNLOCKED = 0,
    HI_OTP_LOCKED,
    HI_OTP_UNKNOWN,
} hi_otp_lock;

hi_s32 otp_func_burn_item(const hi_char *fuse_name, const hi_u8 *value, hi_u32 value_len, hi_bool is_lock);

hi_s32 otp_func_read_item(const hi_char *fuse_name, hi_u8 *value, hi_u32 *value_len);

hi_s32 otp_func_burn_item_off(const hi_char *fuse_name, hi_u32 offset,
                              const hi_u8 *value, hi_u32 value_len, hi_bool is_lock);

hi_s32 otp_func_read_item_off(const hi_char *fuse_name, hi_u32 offset, hi_u8 *value, hi_u32 *value_len);

hi_s32 otp_func_read_item_lock(const hi_char *fuse_name, hi_bool *lock);

hi_s32 otp_func_write_item_lock(const hi_char *fuse_name);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __TEE_OTP_FUNC_H__ */
