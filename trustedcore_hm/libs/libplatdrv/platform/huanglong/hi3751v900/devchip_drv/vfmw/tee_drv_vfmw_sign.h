/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: decoder
 * Author: sdk
 * Create: 2019-04-22
 */

#ifndef __TEE_DRV_VFMW_SIGN_H__
#define __TEE_DRV_VFMW_SIGN_H__

#include "tee_drv_vfmw_ioctl.h"

#define MCU_DAT_SRC_ADDR                0x20800000
#define MCU_DAT_BASE_ADDR               0x27000000
#define MCU_DAT_AFT_DECRYPT_ADDR        (MCU_DAT_BASE_ADDR + VFMW_IMAGE_MAX_LEN)

#define VFMW_EXTER_PUBLIC_KEY_N_LEN     256
#define VFMW_EXTER_PUBLIC_KEY_E_LEN     4
#define TEE_MODULE_ATTR_LEN             200
#define ADSP_ADDR_LEN                   8
#define TEE_KEY_RESERVED                224
#define VFMW_PROTECTION_KEY_LEN         16
#define TEE_KEY_ADDRESS                 (TEE_CA_KEY_ADDRESS + TEE_CA_KEY_SIZE)
#define TEE_KEY_SIZE                    0x400
#define TEE_SECURE_DDR                  1
#define TEE_NON_CACHE                   0
#define TEE_CA_KEY_ADDRESS              0x22200000
#define TEE_CA_KEY_SIZE                 0x400 // 1k
#define TEE_CA_KEY_RESERVED             468
#define TEE_SIG_KEY_LEN                 256
#define VFMW_DOUBLE_SIG_DISABLE         0x3C7896E1

typedef struct {
    hi_u32 certificate_id;
    hi_u32 structure_version;
    hi_u32 reserved_1;
    hi_u8  ext_pub_key_e[VFMW_EXTER_PUBLIC_KEY_E_LEN];
    hi_u8  ext_pub_key_n[VFMW_EXTER_PUBLIC_KEY_N_LEN];
    hi_u32 aux_msid_ext;
    hi_u32 mask_aux_msid_ext;
    hi_u32 aux_version_ext;
    hi_u32 mask_aux_version_ext;
    hi_u32 ta_rootcert_double_sign_en;
    hi_u32 revolist_double_sign_en;
    hi_u32 vmcu_double_sign_en;
    hi_u8  reserved_2[TEE_CA_KEY_RESERVED];
    hi_u8  sig_tee_key[TEE_SIG_KEY_LEN];
} tee_ca_key;

typedef struct {
    hi_u32 certificate_id;
    hi_u32 structure_version;
    hi_u32 tee_code_area_len;
    hi_u8  hisi_tee_root_pub_key_e[VFMW_RSA_PUBLIC_KEY_E_LEN];
    hi_u8  hisi_tee_root_pub_key_n[VFMW_RSA_PUBLIC_KEY_N_LEN];
    hi_u32 tee_msid_ext;
    hi_u32 mask_tee_msid_ext;
    hi_u32 tee_sec_version_ext;
    hi_u32 mask_tee_sec_version_ext;
    hi_u8  tee_protect_key_enc[VFMW_PROTECTION_KEY_LEN];
    hi_u8  smc_protect_key_enc[VFMW_PROTECTION_KEY_LEN];
    hi_u32 tee_func_version;
    hi_u32 smc_area_len;
    hi_u32 tee_reserved_ddr_size;
    hi_u32 tee_runtime_len;
    hi_u8  tee_module_attr[TEE_MODULE_ATTR_LEN];
    hi_u8  adsp_addr[ADSP_ADDR_LEN];
    hi_u8  reserved[TEE_KEY_RESERVED];
    hi_u8  sig_tee_key[TEE_SIG_KEY_LEN];
} tee_key;

hi_s32 tee_drv_vfmw_cmd_ioctl(hi_u32 cmd,  hi_u32 args);

#endif
