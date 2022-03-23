/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Structure for otp fuse item.
 * Author: Linux SDK team
 * Create: 2019-06-24
 */


#ifndef __OTP_DATA_STRUCT_H__
#define __OTP_DATA_STRUCT_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#ifndef OTP_FIELD_NAME_MAX_LEN
#define OTP_FIELD_NAME_MAX_LEN 32
#endif

typedef struct {
    hi_u8 field_name[OTP_FIELD_NAME_MAX_LEN];
    hi_u16 addr;            /* Address offset */
    hi_u16 bit_width;       /* How many bits it possesses */
    hi_u8 start_bit;        /* Start from which bit */
    hi_u8 attibute;         /* bit0: have Locker;  bit 1: has CRC; bit2: has bak-region;
                               bit3: need reset; other bits: reserved,0 */
    hi_u8 priority;         /* priority, 0-99, defult 0, the bigger the later */
    hi_u8 reserved;
    hi_u16 locker_addr;     /* Locker address */
    hi_u8 locker_start_bit; /* Locker start bit */
    hi_u8 locker_bit_width; /* Locker bits width */
    union {
        struct {
            hi_u8 alg;              /* CRC algorithm, 0: crc16 */
            hi_u8 bit_width;        /* CRC bits width */
            hi_u16 addr;            /* CRC address */
            hi_u16 locker_addr;     /* CRC Locker address */
            hi_u8 locker_start_bit; /* CRC Locker start bit */
            hi_u8 locker_bit_width; /* CRC Locker bits width */
        } crc;              /* The BitWidth of CRC is always 8? */
        struct {
            hi_u16 addr;
            hi_u8 start_bit;
            hi_u16 locker_addr;     /* bak Locker address : 0xffff invalid address */
            hi_u8 locker_start_bit; /* bak Locker start bit */
            hi_u8 locker_bit_width; /* bak Locker bits width */
        } bak;              /* The BitWidth of BAK is always same as current item */
        hi_u8 reserved[8]; /* Keep 8 bytes */
    } associated;
} otp_data_item;

otp_data_item *otp_get_data(hi_void);
unsigned int otp_get_data_size(hi_void);
unsigned int otp_get_data_number(hi_void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
