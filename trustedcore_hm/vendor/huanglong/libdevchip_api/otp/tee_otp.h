/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: The file defines the interfaces of otp drive.
 * Author: Hisilicon hisecurity group
 * Create: 2019-12-06
 */

#ifndef __TEE_OTP_H__
#define __TEE_OTP_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */


#define OTP_KEY_LENGTH        16 /* Include rootkey, customer key, privite data etc.. */
#define OTP_ASYM_HASH_LENGTH  32 /* Include rsa/sm2 key hash etc.. */
#define OTP_ID_LENGTH         4  /* Include MSID VERSION_ID etc... */
#define PV_LENGTH             32

struct pv_item {
    hi_u32 value_len;
    hi_u8 value[PV_LENGTH];
};

#define to_upper(c) ((c) - 0x20 * (((c) >= 'a') && ((c) <= 'z')))
#define to_lower(c) ((c) + 0x20 * (((c) >= 'A') && ((c) <= 'Z')))

#define u8tou32(u8_din, u32_dout) \
do { \
    (u32_dout) = ((hi_u32)((u8_din)[3]) << 24) | ((hi_u32)((u8_din)[2]) << 16) | \
                ((hi_u32)((u8_din)[1]) << 8) | ((u8_din)[0]); \
} while (0)

#define u32tou8(u32_din, u8_dout) \
do { \
    ((u8_dout)[0]) = (u32_din) & 0xff; \
    ((u8_dout)[1]) = ((u32_din) >> 8) & 0xff; \
    ((u8_dout)[2]) = ((u32_din) >> 16) & 0xff; \
    ((u8_dout)[3]) = ((u32_din) >> 24) & 0xff; \
} while (0)

hi_s32 otp_pv_item_write(const hi_char *field_name, const hi_u8 *value, hi_u32 value_len);
hi_s32 otp_pv_item_read(const hi_char *field_name, hi_u8 *value, hi_u32 *value_len);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __TEE_OTP_H__ */
