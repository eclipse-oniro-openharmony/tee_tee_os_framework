/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cert driver layer interface declaration
 * Author: Hisilicon hisecurity team
 * Create: 2019-12-08
 */
#ifndef __TEE_DRV_CERT_H__
#define __TEE_DRV_CERT_H__

#include "securec.h"
#include "tee_hal_cert.h"
#include "tee_drv_cert_define.h"
#include "tee_drv_cert_ioctl.h"
#include "drv_klad_com.h"

#ifdef __cplusplus
extern "C" {
#endif

#define  US_CERT_TIMEOUT_DEFAULT  5000000   /* default time:5000^1000us ==> 5s */
#define  US_CERT_TIMEOUT_OTP      10000000  /* otp time:10000^1000us ==> 10s */

struct cert_mgmt {
    hi_u32           io_base;
    hi_u32           io_otp_shadow;

    TEE_UUID         owner;
    hi_mutex         lock;
    hi_mutex         res_lock;
    hi_bool          key_used;
};

struct cert_mgmt *__get_cert_mgmt(hi_void);

hi_s32 cert_ioctl_impl(hi_u32 cmd, hi_void *arg, hi_u32 len);
hi_s32 drv_cert_init(hi_void);
hi_void drv_cert_deinit(hi_void);

hi_s32 hi_drv_cert_init(hi_void);
hi_s32 hi_drv_cert_deinit(hi_void);
hi_s32 hi_drv_cert_reset(hi_void);
hi_s32 hi_drv_cert_lock(hi_cert_res_handle *handle);
hi_s32 hi_drv_cert_unlock(hi_cert_res_handle *handle);
hi_s32 hi_drv_cert_exchange(hi_cert_res_handle *handle, hi_cert_command *cmd);
hi_s32 hi_drv_cert_key_snd_ctl(hi_cert_key_data *ctl);

#ifdef __cplusplus
}
#endif
#endif /* __TEE_DRV_CERT_H__ */
