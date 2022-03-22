/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter rsa keypair generate, rsa crypto and rsa signature api
 * Author: s00294296
 * Create: 2020-03-31
 */
#ifndef __ADAPTER_RSA_H__
#define __ADAPTER_RSA_H__

#include <adapter_common.h>

int adapter_rsa_generate_keypair(uint32_t key_size, const struct memref_t *e_value, bool crt_mode,
				 struct rsa_priv_key_t *key_pair);

int adapter_rsa_encrypt(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
			const struct asymmetric_params_t *rsa_params,
			const struct memref_t *data_in, struct memref_t *data_out);

int adapter_rsa_decrypt(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
			const struct asymmetric_params_t *rsa_params,
			const struct memref_t *data_in, struct memref_t *data_out);

int adapter_rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
			    const struct asymmetric_params_t *rsa_params,
			    const struct memref_t *digest, struct memref_t *signature);

int adapter_rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
			      const struct asymmetric_params_t *rsa_params,
			      const struct memref_t *digest, const struct memref_t *signature);

#endif

