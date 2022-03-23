/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:OTP comon macro and API.
 * Author: Linux SDK team
 * Create: 2019/06/20
 */
#ifndef __DRV_OTP_H__
#define __DRV_OTP_H__

#include "drv_otp_define.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* end of #ifdef __cplusplus */

struct otp_mgmt {
    struct MUTEX   lock;
    hi_u32         io_base;
};
struct time_us {
    hi_ulong tv_sec;
    hi_ulong tv_usec;
};
struct otp_mgmt *__get_otp_mgmt(hi_void);

hi_s32 drv_otp_init(hi_void);
hi_void drv_otp_deinit(hi_void);
hi_s32 otp_ioctl_impl(unsigned int cmd, hi_void *arg, hi_u32 len);

hi_void otp_timestamp(struct time_us *time);
hi_void otp_get_curr_cost(hi_char *str, struct time_us *time_b);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* end of #ifdef __cplusplus */

#endif /* end of #ifndef __DRV_OTP_H__ */
