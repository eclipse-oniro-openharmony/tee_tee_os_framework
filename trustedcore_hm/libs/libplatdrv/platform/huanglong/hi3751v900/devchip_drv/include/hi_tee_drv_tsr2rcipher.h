/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee drv tsr2rcipher head file.
 * Author: sdk
 * Create: 2019-08-02
 */

#ifndef __HI_TEE_DRV_TSR2RCIPHER_H__
#define __HI_TEE_DRV_TSR2RCIPHER_H__

#include "hi_type_dev.h"
#include "tee_drv_ioctl_tsr2rcipher.h"

#ifdef __cplusplus
extern "C" {
#endif

hi_s32 hi_drv_tsr2rcipher_get_capability(tsr2rcipher_capability *cap);
hi_s32 hi_drv_tsr2rcipher_create(const tsr2rcipher_attr *tsc_attr, hi_handle *handle);
hi_s32 hi_drv_tsr2rcipher_destroy(hi_handle handle);
hi_s32 hi_drv_tsr2rcipher_get_attr(hi_handle handle, tsr2rcipher_attr *tsc_attr);
hi_s32 hi_drv_tsr2rcipher_set_attr(hi_handle handle, const tsr2rcipher_attr *tsc_attr);
hi_s32 hi_drv_tsr2rcipher_get_keyslot_handle(hi_handle tsc_handle, hi_handle *ks_handle);
hi_s32 hi_drv_tsr2rcipher_attach_keyslot(hi_handle tsc_handle, hi_handle ks_handle);
hi_s32 hi_drv_tsr2rcipher_detach_keyslot(hi_handle tsc_handle, hi_handle ks_handle);
hi_s32 hi_drv_tsr2rcipher_set_iv(hi_handle handle, tsr2rcipher_iv_type iv_type, hi_u8 *iv, hi_u32 iv_len);
hi_s32 hi_drv_tsr2rcipher_encrypt(hi_handle handle, hi_u64 src_buf, hi_u64 dst_buf, hi_u32 data_len);
hi_s32 hi_drv_tsr2rcipher_decrypt(hi_handle handle, hi_u64 src_buf, hi_u64 dst_buf, hi_u32 data_len);

#ifdef __cplusplus
}
#endif

#endif  /* __HI_TEE_DRV_TSR2RCIPHER_H__ */

