/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:KS comon macro and API.
 * Author: Linux SDK team
 * Create: 2019/06/22
 */
#ifndef __DRV_KS_H__
#define __DRV_KS_H__

#include "drv_keyslot_define.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* end of #ifdef __cplusplus */

#define KS_TSCIPHER_SLOT_NUM 256
#define KS_MCIPHER_SLOT_NUM  15
#define KS_HMAC_SLOT_NUM     1

struct ks_mgmt {
    mutex   lock;
    hi_void        *io_base;
};

hi_s32 ks_ioctl_impl(unsigned int cmd, hi_void *arg, hi_u32 len);
hi_s32 drv_ks_init(hi_void);
hi_void _mutex_lock(hi_void);
hi_void _mutex_unlock(hi_void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* end of #ifdef __cplusplus */

#endif /* end of #ifndef __DRV_KS_H__ */
