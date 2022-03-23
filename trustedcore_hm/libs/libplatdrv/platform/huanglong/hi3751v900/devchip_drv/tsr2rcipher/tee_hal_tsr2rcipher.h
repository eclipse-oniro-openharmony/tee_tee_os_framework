/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee hal tsr2rcipher head file.
 * Author: sdk
 * Create: 2019-08-02
 */

#ifndef __TEE_HAL_TSR2RCIPHER_H__
#define __TEE_HAL_TSR2RCIPHER_H__

#include "hi_type_dev.h"
#include "tee_drv_tsr2rcipher_define.h"

#ifdef __cplusplus
extern "C" {
#endif

hi_void tee_tsc_hal_init_hw(hi_void);
hi_void tee_tsc_hal_deinit_hw(hi_void);

#ifdef TSR2RCIPHER_SMMU_SUPPORT
hi_void tee_tsc_hal_en_mmu(tee_tsr2rcipher_mgmt *mgmt);
hi_void tee_tsc_hal_dis_mmu(tee_tsr2rcipher_mgmt *mgmt);
#else
static inline hi_void tee_tsc_hal_en_mmu(tee_tsr2rcipher_mgmt *mgmt) {}
static inline hi_void tee_tsc_hal_dis_mmu(tee_tsr2rcipher_mgmt *mgmt) {}
#endif

hi_void tee_tsc_hal_top_set_int(tee_tsr2rcipher_mgmt *mgmt, hi_bool rx_int, hi_bool tx_int, hi_bool cipher_int);

hi_void tee_tsc_hal_rx_config(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, enum tsc_buf_type buf_type);
hi_bool tee_tsc_hal_rx_get_dsptor_status(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id);
hi_void tee_tsc_hal_rx_set_buf(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_u64 src_buf_addr, hi_u32 src_buf_len);
hi_void tee_tsc_hal_tx_config(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, enum tsc_buf_type buf_type);
hi_bool tee_tsc_hal_tx_get_dsptor_status(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id);
hi_void tee_tsc_hal_tx_set_buf(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_u64 dst_buf_addr, hi_u32 dst_buf_len);

hi_void tee_tsc_hal_set_sec_chan(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_bool rx_is_sec, hi_bool tx_is_sec);
hi_void tee_tsc_hal_clr_chan(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id);
hi_void tee_tsc_hal_set_mode_ctl(tee_tsr2rcipher_mgmt *mgmt, tsr2rcipher_ch *rch,
    hi_u32 id, enum tsc_crypt_type crypt_type);
hi_void tee_tsc_hal_en_mode_ctl(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id);
hi_void tee_tsc_hal_dis_mode_ctl(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id);
hi_void tee_tsc_hal_lock_config(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_bool is_tee_lock);
hi_void tee_tsc_hal_lock_deconfig(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id);

hi_u32  tee_tsc_hal_top_get_tx_raw_int_status(tee_tsr2rcipher_mgmt *mgmt);
hi_void tee_tsc_hal_top_cls_tx_int_status(tee_tsr2rcipher_mgmt *mgmt);
hi_u32  tee_tsc_hal_tx_get_dsc_rd_total_int_status(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id);
hi_void tee_tsc_hal_tx_cls_dsc_rd_total_int_status(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id);

#ifdef __cplusplus
}
#endif

#endif /* __TEE_HAL_TSR2RCIPHER_H__ */

