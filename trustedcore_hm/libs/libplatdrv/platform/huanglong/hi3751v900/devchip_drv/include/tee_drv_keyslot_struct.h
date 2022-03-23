/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Key slot drvier level head file.
 * Author: Linux SDK team
 * Create: 2019/06/22
 */

#ifndef __TEE_DRV_KS_STRUCT_H__
#define __TEE_DRV_KS_STRUCT_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    HI_KEYSLOT_TYPE_TSCIPHER = 0x00,
    HI_KEYSLOT_TYPE_MCIPHER,
    HI_KEYSLOT_TYPE_HMAC,
    HI_KEYSLOT_TYPE_MAX
} hi_keyslot_type;

typedef union {
    struct {
        hi_u8 type     : 7;
        hi_u8 secure   : 1;
    } bits;
    hi_u8 u8;
} hi_keyslot_priv_attr;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __HI_DRV_KEYSLOT_H__ */


