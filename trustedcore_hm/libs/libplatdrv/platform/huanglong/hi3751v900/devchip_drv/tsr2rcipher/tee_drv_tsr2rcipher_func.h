/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee drv tsr2rcipher function head file.
 * Author: sdk
 * Create: 2019-08-02
 */

#ifndef __TEE_DRV_TSR2RCIPHER_FUNC_H__
#define __TEE_DRV_TSR2RCIPHER_FUNC_H__

#include "hi_type_dev.h"
#include "tee_drv_ioctl_tsr2rcipher.h"

#ifdef __cplusplus
extern "C" {
#endif

hi_s32 tsr2rcipher_get_capability_impl(tsr2rcipher_capability *cap);
hi_s32 tsr2rcipher_create_impl(const tsr2rcipher_attr *tsc_attr, hi_handle *handle);
hi_s32 tsr2rcipher_destroy_impl(hi_handle handle);
hi_s32 tsr2rcipher_get_attr_impl(hi_handle handle, tsr2rcipher_attr *tsc_attr);
hi_s32 tsr2rcipher_set_attr_impl(hi_handle handle, const tsr2rcipher_attr *tsc_attr);
hi_s32 tsr2rcipher_get_keyslot_handle_impl(hi_handle tsc_handle, hi_handle *ks_handle);
hi_s32 tsr2rcipher_attach_keyslot_impl(hi_handle tsc_handle, hi_handle ks_handle);
hi_s32 tsr2rcipher_detach_keyslot_impl(hi_handle tsc_handle, hi_handle ks_handle);
hi_s32 tsr2rcipher_set_iv_impl(hi_handle handle, tsr2rcipher_iv_type iv_type, hi_u8 *iv, hi_u32 iv_len);
hi_s32 tsr2rcipher_encrypt_impl(hi_handle handle, hi_u64 src_addr, hi_u64 dst_addr, hi_u32 data_len);
hi_s32 tsr2rcipher_decrypt_impl(hi_handle handle, hi_u64 src_addr, hi_u64 dst_addr, hi_u32 data_len);
hi_s32 tsr2rcipher_mod_init_impl(hi_void);
hi_s32 tsr2rcipher_mod_exit_impl(hi_void);

#ifdef __cplusplus
}
#endif

#endif  /* __TEE_DRV_TSR2RCIPHER_FUNC_H__ */
