/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee drv tsr2rcipher private struct and macro define
 * Author: sdk
 * Create: 2020-01-23
 */

#ifndef __TEE_DRV_TSR2RCIPHER_DEFINE_H__
#define __TEE_DRV_TSR2RCIPHER_DEFINE_H__

#include "hi_type_dev.h"
#include "hi_bitmap.h"
#include "hi_log.h"

#include "hi_tee_module_id.h"
#include "hi_tee_drv_os_hal.h"

#include "tee_drv_ioctl_tsr2rcipher.h"
#include "tee_drv_tsr2rcipher_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TSC_INVALID_HANDLE 0xFFFFFFFF

/* HANDLE macro */
#define TSC_HANDLE_MAGIC        (0xB)
#define tsc_id_2_handle(id)     ((HI_ID_TSR2RCIPHER << 24) | (TSC_HANDLE_MAGIC << 16) | ((id) & 0x0000ffff))
#define tsc_handle_2_id(handle) ((handle) & 0x0000ffff)

#define tsc_check_handle(handle) do {                            \
    if ((((handle) >> 24) & 0x000000ff) != HI_ID_TSR2RCIPHER || \
        (((handle) >> 16) & 0x000000ff) != TSC_HANDLE_MAGIC) {  \
        hi_log_err("invalid tsr2rcipher handle!\n");     \
        return HI_FAILURE;                                       \
    }                                                            \
} while (0)

#define tsc_check_ks(handle) do {                             \
    if ((((handle) >> 24) & 0x000000ff) != HI_ID_KEYSLOT) { \
        hi_log_err("invalid keyslot handle!\n");      \
        return HI_FAILURE;                                    \
    }                                                         \
} while (0)

#define tsc_check_ch_id(chan_id) do {                \
    if ((chan_id) >= TSR2RCIPHER_CH_CNT) {           \
        hi_log_err("invalid channel id!\n"); \
        return HI_FAILURE;                           \
    }                                                \
} while (0)

/* general struct */
enum tsc_buf_type {
    TSC_BUF_TYPE_LINK = 0,
    TSC_BUF_TYPE_CYCLE = 1,
    TSC_BUF_TYPE_MAX
};

enum tsc_core_type {
    TSC_CORE_TYPE_AES  = 0,
    TSC_CORE_TYPE_SMS4 = 1,
    TSC_CORE_TYPE_MAX
};

enum tsc_crypt_type {
    TSC_CRYPT_TYPE_EN = 0,
    TSC_CRYPT_TYPE_DE = 1,
    TSC_CRYPT_TYPE_MAX
};

typedef struct {
    struct hi_tee_hal_mutex lock_ch;
    hi_handle               ch_handle;

    tsr2rcipher_alg         alg;
    tsr2rcipher_mode        mode;
    hi_bool                 is_crc_check;

    hi_bool                 is_create_ks;
    hi_handle               ks_handle;
    hi_bool                 is_odd_key;

    enum tsc_core_type      core_type;   /* AES or SMS4 */
    tsr2rcipher_iv_type     iv_type;     /* even or odd */
} tsr2rcipher_ch;

typedef struct {
    hi_u32                      io_base;
    hi_u64                      cb_ttbr;

    tsr2rcipher_ch              ch_info[TSR2RCIPHER_CH_CNT];
    hi_u32                      ch_cnt;
    struct hi_tee_hal_mutex     lock_all_ch;
    DECLARE_BITMAP(ch_bitmap, TSR2RCIPHER_CH_CNT);
} tee_tsr2rcipher_mgmt;

#ifdef __cplusplus
}
#endif

#endif  /* __TEE_DRV_TSR2RCIPHER_DEFINE_H__ */
