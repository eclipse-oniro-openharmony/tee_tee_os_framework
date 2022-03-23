/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: key enhanced definitions
 * Create: 2021-01-09
 */
#ifndef __KM_KEY_ENHANCED_H
#define __KM_KEY_ENHANCED_H
#include "keymaster_defs.h"
#include "keyblob.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY

TEE_Result unsupport_enhanced_key(const keymaster_key_param_set_t *param);
TEE_Result get_inse_factor(const keymaster_key_param_set_t *params_enforced, keymaster_blob_t *inse_factor);
TEE_Result re_encrypt_keyblob(const struct kb_crypto_factors *old_factors, const struct kb_crypto_factors *new_factors,
    const keyblob_head *keyblob_old, keyblob_head *keyblob_new, keymaster_blob_t *keyblob_gp);
#endif
#endif
