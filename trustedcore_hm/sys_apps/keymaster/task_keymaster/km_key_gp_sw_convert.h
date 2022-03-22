/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key format transfer between GP and software engine header
 * Create: 2020-11-09
 */
#ifndef __KM_KEY_GP_SW_CONVERT_H
#define __KM_KEY_GP_SW_CONVERT_H
#include "tee_internal_api.h"
#include "crypto_wrapper.h"
TEE_Result convert_ec_gp2sw_key(TEE_ObjectHandle key_obj, ecc_pub_key_t *sw_pubkey_ec);
int32_t ec_nist_curve2swcurve(TEE_ECC_CURVE ec_curve, uint32_t *sw_ec_curve);
TEE_Result rsa_get_pub_local(rsa_pub_key_t *sw_pubkey_rsa, TEE_ObjectHandle *key_obj);
#endif