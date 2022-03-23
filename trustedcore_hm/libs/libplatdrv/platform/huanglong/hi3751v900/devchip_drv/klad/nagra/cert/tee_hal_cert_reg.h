/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cert register define
 * Author: Hisilicon hisecurity team
 * Create: 2019-08-23
 */
#ifndef __TEE_HAL_CERT_REG_H__
#define __TEE_HAL_CERT_REG_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AKL_LOCK_IDLE = 0x0,
    AKL_LOCK_TEE  = 0x1,
    AKL_LOCK_REE  = 0x2,
    AKL_LOCK_DEAD = 0x3, /* HW has detected akl_lock_status is attacted. all registers cann't be accessed any more. */
} cert_lock_stat;

#define AKL_REG_RANGE            0x200
#define AKL_REG_BASE             (0x00b09000 + 0xB0000000)

#define OTP_SHADOW_REG_RANGE       0x1000
#define OTP_SHADOW_REG_BASE        (0x00b00000 + 0xB0000000)

/*
 * 0x5f[bit4~bit5]: Privilegedmode control.
 * 0xa: non-privileged mode
 * others: privileged mode. (It will be set 0xf)
 */
#define AKL_PV_SHADOW_REG       (OTP_SHADOW_REG_BASE + 0x5c)

/* rw xst of eight data input registers for the CERT IP, read/write, for a total of 256 bits. */
#define DATA_IN_0               (AKL_REG_BASE + 0x00) /* rw */
#define DATA_IN_1               (AKL_REG_BASE + 0x04) /* rw */
#define DATA_IN_2               (AKL_REG_BASE + 0x08) /* rw */
#define DATA_IN_3               (AKL_REG_BASE + 0x0C) /* rw */
#define DATA_IN_4               (AKL_REG_BASE + 0x10) /* rw */
#define DATA_IN_5               (AKL_REG_BASE + 0x14) /* rw */
#define DATA_IN_6               (AKL_REG_BASE + 0x18) /* rw */
#define DATA_IN_7               (AKL_REG_BASE + 0x1C) /* rw */

/* ro xst of eight data output registers for the CERT IP, read/write, for a total of 256 bits. */
#define DATA_OUT_0              (AKL_REG_BASE + 0x20) /* ro */
#define DATA_OUT_1              (AKL_REG_BASE + 0x24) /* ro */
#define DATA_OUT_2              (AKL_REG_BASE + 0x28) /* ro */
#define DATA_OUT_3              (AKL_REG_BASE + 0x2C) /* ro */
#define DATA_OUT_4              (AKL_REG_BASE + 0x30) /* ro */
#define DATA_OUT_5              (AKL_REG_BASE + 0x34) /* ro */
#define DATA_OUT_6              (AKL_REG_BASE + 0x38) /* ro */
#define DATA_OUT_7              (AKL_REG_BASE + 0x3C) /* ro */

#define AKL_STATUS              (AKL_REG_BASE + 0x40) /* ro CERT IP status register */
#define AKL_CAMMAND             (AKL_REG_BASE + 0x44) /* rw command register */

/* interrupt */
#define AKL_INTERRUPT           (AKL_REG_BASE + 0x48)
#define AKL_INT_EN              (AKL_REG_BASE + 0x80)

/* key security attribute */
#define AKL_SEC_EN              (AKL_REG_BASE + 0x84)

#define AKL_KEY_SEND_CTRL       (AKL_REG_BASE + 0x90)
#define AKL_KEY_SEND_NODE       (AKL_REG_BASE + 0x94)
#define AKL_KEY_META_DATA       (AKL_REG_BASE + 0x98)

/*
 * Before setting AKL to generate content key, TEE/REE CPU should firstly set akl_lock to 1,
 * to let AKL to be in TEE lock or REE lock status.
 * 0: unlock AKL by TEE/REE CPU. Only when akl_lock_status = 2'b01, TEE CPU can set this bit to 0.
 * Only when akl_lock_status = 2'b10, REE CPU can set this bit to 0.
 * 1: lock AKL by TEE/REE CPU. only when akl_lock_status = 2'b00, TEE/REE CPU can set this bit to 1;
 */
#define AKL_LOCK                (AKL_REG_BASE + 0x100)

/*
 * Before setting AKL to generate content key, TEE/REE CPU should firstly set akl_lock to 1,
 * to let AKL to be in TEE lock or REE lock status.
 * 2'b00: IDLE status, means both TEE/REE can use AKL.
 * 2'b01: TEE LOCK status, means only TEE can use AKL.
 * 2'b10: REE LOCK status, means only REE can use AKL.
 * 2'b11: invalid value, this value will not be occured.
 */
#define AKL_LOCK_STATE          (AKL_REG_BASE + 0x104)

/*
 * If AKL generate a key and master start a command to send this key to target module, but at this time target module
 * is being reset, if tartget module keep in reset over 262us, c1_1_send_time_out will be set to 1.
 */
#define AKL_DBG_STATE           (AKL_REG_BASE + 0x108)

#define AKL_RST_REQ             (AKL_REG_BASE + 0x110)
#define AKL_GEN_ERROR           (AKL_REG_BASE + 0x118)
#define AKL_KC_SEND_ERROR       (AKL_REG_BASE + 0x120)

/* define the union cert_akl_status */
typedef union {
    struct {
        hi_u32 cert_ip_err       : 1; /* [0]CERT IP error flag:  0:no error  1: generic error */
        hi_u32 key_output        : 1; /* [1]key output interface info 0: no key  1: key pending on the bus */
        hi_u32 reserved          : 30;
    } bits;
    hi_u32 u32;
} akl_status;

/* define the union akl_interrupt */
typedef union {
    struct {
        hi_u32 interrupt         : 1;  /* [0] */
        hi_u32 reserved          : 31; /* [31..1] */
    } bits;
    hi_u32 u32;
} akl_interrupt;

/* define the union akl_int_en */
typedef union {
    struct {
        hi_u32 interrupt_en      : 1;  /* [0] */
        hi_u32 reserved          : 31; /* [31..1] */
    } bits;
    hi_u32 u32;
} akl_int_en;

/* define the union akl_sec_en */
typedef union {
    struct {
        hi_u32 akl_sec_en        : 1;  /* [0] */
        hi_u32 reserved          : 31; /* [31..1] */
    } bits;
    hi_u32 u32;
} akl_sec_en;

/* define the union akl_key_send_ctl */
typedef union {
    struct {
        hi_u32 send_start        : 1;  /* [0] */
        hi_u32 port_sel          : 2;  /* [2:1] 0b00 TSCipher, 0b01 MCipher */
        hi_u32 reserved          : 1;  /* [3] reserved */
        hi_u32 key_addr          : 8;  /* [11:4] [bit 4] 0: the current cw is even; 1: the current cw is odd. */
        hi_u32 dsc_code          : 8;  /* [19:12] 0x0: CSA2 0x10: CSA3 0x2X: AES 0x7X: TDES 0x91: ASA 0x92:ASA light */
        hi_u32 key_addr_higher   : 2;  /* [21:20] As the highest 2 bit key addr of key slot. */
        hi_u32 reserved_1        : 2;  /* [23:22] reserved */
        hi_u32 sns               : 1;  /* [24] */
        hi_u32 ss                : 1;  /* [25] */
        hi_u32 dns               : 1;  /* [26] */
        hi_u32 ds                : 1;  /* [27] */
        hi_u32 reserved_2        : 4;  /* [31:28] reserved */
    } bits;
    hi_u32 u32;
} akl_key_send_ctl;

/* define the union akl_key_send_done */
typedef union {
    struct {
        hi_u32 all_done          : 1;  /* [0] */
        hi_u32 reserved          : 31; /* [31..1] */
    } bits;
    hi_u32 u32;
} akl_key_send_done;

/* define the union akl_lock */
typedef union {
    struct {
        hi_u32 akl_lock          : 1;  /* [0] */
        hi_u32 reserved          : 31; /* [31..1] */
    } bits;
    hi_u32 u32;
} akl_lock;

/* define the union akl_lock_state */
typedef union {
    struct {
        hi_u32 akl_lock_status   : 2;  /* [1:0] */
        hi_u32 reserved          : 30; /* [31..2] */
    } bits;
    hi_u32 u32;
} akl_lock_state;


/* define the union akl_dbg_state */
typedef union {
    struct {
        hi_u32 send_time_out     : 1;  /* [0] */
        hi_u32 reserved          : 31; /* [31..1] */
    } bits;
    hi_u32 u32;
} akl_dbg_state;


/* define the union akl_rst_req */
typedef union {
    struct {
        hi_u32 akl_rst_req       : 1;  /* [0] */
        hi_u32 reserved          : 31; /* [31..1] */
    } bits;
    hi_u32 u32;
} akl_rst_req;

/* define the union akl_gen_error */
typedef union {
    struct {
        hi_u32 alg_error         : 1;  /* [0] */
        hi_u32 port_sel_error    : 1;  /* [1] */
        hi_u32 invalid_key_error : 1;  /* [2] */
        hi_u32 reserved          : 29; /* [31..3] */
    } bits;
    hi_u32 u32;
} akl_gen_error;

/* define the union akl_kc_send_error */
typedef union {
    struct {
        hi_u32 tpp_lock_fail                : 1; /* [0] */
        hi_u32 hpp_lock_fail                : 1; /* [1] */
        hi_u32 tee_lock_fail                : 1; /* [2] */
        hi_u32 ree_lock_fail                : 1; /* [3] */
        hi_u32 csa2_hardonly_fail           : 1; /* [4] */
        hi_u32 csa3_hardonly_fail           : 1; /* [5] */
        hi_u32 aes_hardonly_fail            : 1; /* [6] */
        hi_u32 sm4_hardonly_fail            : 1; /* [7] */
        hi_u32 tdes_hardonly_fail           : 1; /* [8] */
        hi_u32 multi2_hardonly_fail         : 1; /* [9] */
        hi_u32 csa2_disable_fail            : 1; /* [10] */
        hi_u32 csa3_disable_fail            : 1; /* [11] */
        hi_u32 aes_disable_fail             : 1; /* [12] */
        hi_u32 des_disable_fail             : 1; /* [13] */
        hi_u32 sm4_disable_fail             : 1; /* [14] */
        hi_u32 tdes_disable_fail            : 1; /* [15] */
        hi_u32 multi2_disable_fail          : 1; /* [16] */
        hi_u32 asa_disable_fail             : 1; /* [17] */
        hi_u32 buffer_security_fail         : 1; /* [18] */
        hi_u32 reserved                     : 1; /* [19] */
        hi_u32 encrypt_decrypt_fail         : 1; /* [20] */
        hi_u32 send_key_time_out            : 1; /* [21] */
        hi_u32 reserved_1                   : 11; /* [31..21] */
    } bits;
    hi_u32 u32;
} akl_kc_send_error;


#ifdef __cplusplus
}
#endif

#endif /* __TEE_HAL_CERT_REG_H__ */

