/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cert hal layer interface declaration
 * Author: Hisilicon hisecurity team
 * Create: 2019-12-08
 */
#ifndef __TEE_HAL_CERT_H__
#define __TEE_HAL_CERT_H__

#include "tee_hal_cert_reg.h"
#include "tee_drv_cert_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    hi_u32 data[DATA_NUM];
} akl_data;

hi_u32 hal_cert_read_reg(const hi_u32 addr);
hi_void hal_cert_write_reg(const hi_u32 addr, const hi_u32 val);
hi_u32 hal_cert_get_status(hi_void);
hi_bool hal_cert_key_pending(hi_void);
hi_bool hal_cert_ip_err(hi_void);
hi_void hal_cert_set_command(hi_u32 cmd);
hi_u32 hal_cert_get_command(hi_void);
hi_u32 hal_cert_get_metadata(hi_void);
hi_s32 hal_cert_wait_done(hi_cert_timeout time_out);
hi_void hal_cert_lock(hi_void);
hi_void hal_cert_unlock(hi_void);
hi_bool hal_cert_is_locked(hi_void);
hi_bool hal_cert_is_unlocked(hi_void);
hi_u32 hal_cert_key_send(hi_void);
hi_s32 hal_cert_key_send_ctl(akl_key_send_ctl reg);
hi_u32 hal_cert_get_key_send_ctl(hi_void);
hi_s32 hal_cert_check_key_status(hi_void);
hi_u32 hal_cert_gen_err(hi_void);
hi_u32 hal_cert_gen_kc_err(hi_void);
hi_u32 hal_cert_meta_data(hi_void);
hi_void hal_cert_get_data_in(akl_data *data_in);
hi_void hal_cert_set_data_in(const akl_data *data_in);
hi_void hal_cert_get_data_out(akl_data *data_out);
hi_void hal_cert_reset(hi_void);
hi_void hal_cert_set_sec_en(hi_void);
hi_void hal_cert_set_sec_dis(hi_void);
hi_bool hal_cert_get_sec_stat(hi_void);
hi_bool hal_cert_pv_activated(hi_void);
hi_s32 hal_cert_init(hi_void);
hi_void hal_cert_deinit(hi_void);

#ifdef __cplusplus
}
#endif
#endif /* __TEE_HAL_CERT_H__ */


