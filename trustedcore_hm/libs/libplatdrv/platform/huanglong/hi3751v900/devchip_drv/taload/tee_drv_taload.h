/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: drv function file for TALOAD
 * Author: BSP group
 * Create: 2020-01-17
 */

#ifndef __TEE_DRV_TALOAD_H__
#define __TEE_DRV_TALOAD_H__

#include "hi_type_dev.h"
#include "tee_drv_taload_ioctl.h"
#include "tee_drv_common_ioctl.h"

#define hi_error_taload(fmt...)        hi_tee_drv_hal_printf(fmt)
#define TEE_CA_KEY_ADDRESS             0x22200000
#define TEE_CA_KEY_SIZE                0x400
#define TEE_CA_KEY_RESERVED            468
#define TALOAD_PROTECTION_KEY_LEN      16
#define TEE_KEY_ADDRESS               (TEE_CA_KEY_ADDRESS + TEE_CA_KEY_SIZE)
#define TEE_KEY_SIZE                   0x400
#define TEE_MODULE_ATTR_LEN            200
#define TEE_KEY_RESERVED               224
#define ADSP_ADDR_LEN                  8
#define TALOAD_SIGNATURE_LEN           256
#define TEE_SECURE_DDR                 1
#define TEE_NON_CACHE                  0

typedef struct {
    hi_u32 certificate_id;
    hi_u32 structure_version;
    hi_u32 reserved_1;
    hi_u8  ext_pub_key_e[TALOAD_RSA_PUBLIC_KEY_E_LEN];
    hi_u8  ext_pub_key_n[TALOAD_RSA_PUBLIC_KEY_N_LEN];
    hi_u32 aux_msid_ext;
    hi_u32 mask_aux_msid_ext;
    hi_u32 aux_version_ext;
    hi_u32 mask_aux_version_ext;
    hi_u32 ta_rootcert_double_sign_en;
    hi_u32 revolist_double_sign_en;
    hi_u32 vmcu_double_sign_en;
    hi_u8  reserved_2[TEE_CA_KEY_RESERVED];
    hi_u8  sig_tee_key[TALOAD_SIGNATURE_LEN];
} tee_ca_key;

typedef struct {
    hi_u32 certificate_id;
    hi_u32 structure_version;
    hi_u32 tee_code_area_len;
    hi_u8  hisi_tee_root_pub_key_e[TALOAD_RSA_PUBLIC_KEY_E_LEN];
    hi_u8  hisi_tee_root_pub_key_n[TALOAD_RSA_PUBLIC_KEY_N_LEN];
    hi_u32 tee_msid_ext;
    hi_u32 mask_tee_msid_ext;
    hi_u32 tee_sec_version_ext;
    hi_u32 mask_tee_sec_version_ext;
    hi_u8  tee_protect_key_enc[TALOAD_PROTECTION_KEY_LEN];
    hi_u8  smc_protect_key_enc[TALOAD_PROTECTION_KEY_LEN];
    hi_u32 tee_func_version;
    hi_u32 smc_area_len;
    hi_u32 tee_reserved_ddr_size;
    hi_u32 tee_runtime_len;
    hi_u8  tee_module_attr[TEE_MODULE_ATTR_LEN];
    hi_u8  adsp_addr[ADSP_ADDR_LEN];
    hi_u8  reserved[TEE_KEY_RESERVED];
    hi_u8  sig_tee_key[TALOAD_SIGNATURE_LEN];
} tee_key;

#endif
