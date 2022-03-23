/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: for crys_cipher_common
 * Author: zhaoguihong
 * Create: 2019-06-18
 */

#ifndef __CRYS_CRYPTO_COMMON_H_
#define __CRYS_CRYPTO_COMMON_H_
#include "hi_type_dev.h"
#include "dx_pal_types.h"
#include "crys_error.h"
#include "crys_rsa_types.h"
#include "crys_ecpki_types.h"
#include "crys_ecpki_error.h"
#include "drv_osal_lib.h"

#define RSA_MAX_RSA_KEY_LEN           512
#define ECC_MAX_KEY_SIZE              72

#define malloc(x) hi_tee_drv_hal_malloc((x))
#define free(x)   hi_tee_drv_hal_free((x))

hi_u32 crys_get_bit_num(hi_u8 *bits, hi_u32 num_len);
hi_s32 crys_bn2bin(const hi_u32 *bn, hi_u8 *bin, hi_s32 len);
hi_s32 crys_bin2bn(hi_u32 *bn, const hi_u8 *bin, hi_s32 len);
hi_s32 crys_get_random_number(hi_u8 *random, hi_u32 size);
hi_s32 crys_ecp_load_group(CRYS_ECPKI_DomainID_t domain_id, ecc_param_t *ecc_param, hi_u32 *pad_len);
hi_s32 crys_aes_set_clear_key(hi_handle cipher, const hi_u8 *key, hi_u32 keylen);

#endif

