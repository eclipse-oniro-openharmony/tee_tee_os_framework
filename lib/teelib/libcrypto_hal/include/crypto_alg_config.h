/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: algorithm configration
 * Create: 2020-06-08
 */
#ifndef CRYPTO_ALG_CONFIG_H
#define CRYPTO_ALG_CONFIG_H

#include <tee_defines.h>

bool crypto_check_alg_valid(uint32_t alg, uint32_t mode);
uint32_t crypto_get_op_class(uint32_t alg);
TEE_Result crypto_check_keysize(uint32_t algorithm, uint32_t max_key_size);
bool crypto_check_keytype_valid(uint32_t algo, uint32_t type);
bool crypto_check_alg_supported(uint32_t alg, uint32_t element);
bool crypto_object_type_supported(uint32_t object_type);
TEE_Result check_if_unsafe_alg(uint32_t alg, uint32_t key_size);
TEE_Result check_if_unsafe_type(uint32_t obj_type, uint32_t key_size);
#endif
