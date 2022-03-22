/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter ecc keypair generate, ecc crypto and ecc signature api
 * Author: s00294296
 * Create: 2020-03-31
 */
#ifndef __ADAPTER_ECC_H__
#define __ADAPTER_ECC_H__

#include <adapter_common.h>

int adapter_ecc_generate_keypair(uint32_t keysize, uint32_t curve_id,
				 struct ecc_pub_key_t *public_key,
				 struct ecc_priv_key_t *private_key);

int adapter_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
			const struct asymmetric_params_t *ec_params,
			const struct memref_t *data_in, struct memref_t *data_out);

int adapter_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
			const struct asymmetric_params_t *ec_params,
			const struct memref_t *data_in, struct memref_t *data_out);

int adapter_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
			    const struct asymmetric_params_t *ec_params,
			    const struct memref_t *digest, struct memref_t *signature);

int adapter_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
			      const struct asymmetric_params_t *ec_params,
			      const struct memref_t *digest, const struct memref_t *signature);

#endif

