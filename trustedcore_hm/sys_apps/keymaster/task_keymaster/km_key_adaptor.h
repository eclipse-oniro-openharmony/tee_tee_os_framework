/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key format transfer for different cipher engine header
 * Create: 2020-11-09
 */
#ifndef __KM_KEY_ADAPTOR_H
#define __KM_KEY_ADAPTOR_H

/* convert private gp format to sw struct */
TEE_Result covert_ec_prvkey_gp2sw(TEE_ObjectHandle key, ecc_priv_key_t *ecc_priv_key);

/* convert pubkey gp format to sw struct */
TEE_Result covert_ec_pubkey_gp2sw(TEE_ObjectHandle key, ecc_pub_key_t *ecc_pub_key);
/* convert rsa private gp format to sw struct */
TEE_Result covert_rsa_prvkey_gp2sw(TEE_ObjectHandle key, rsa_priv_key_t *rsa_priv_key);
#endif