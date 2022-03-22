/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Crypto ext api header file
 * Create: 2020-02-21
 */
#ifndef CRYPTO_EXT_API_H
#define CRYPTO_EXT_API_H
#include <stdint.h>
#include <tee_defines.h>
enum KDF_HASH_MODE {
    KDF_HASH_SHA1   = 0,
    KDF_HASH_SHA224 = 1,
    KDF_HASH_SHA256 = 2,
    KDF_HASH_SHA384 = 3,
    KDF_HASH_SHA512 = 4,
};

enum KDF_DERIVFUNC_MODE {
    KDF_ASN1_DERIVMODE          = 0,
    KDF_CONCATDERIVMODE         = 1,
    KDF_X963_DERIVMODE          = KDF_CONCATDERIVMODE,
    KDF_OMADRM_DERIVMODE        = 2,
    KDF_ISO18033_KDF1_DERIVMODE = 3,
    KDF_ISO18033_KDF2_DERIVMODE = 4,
};

struct kdf_params_t {
    uint8_t *key;
    uint32_t key_size;
    uint8_t *out;
    uint32_t out_size;
};

/*
 * @ingroup TEE_EXT_API
 * @brief  Do cmac derive key
 *
 * @param [IN] input data
 * @param [IN] the length of input data
 * @param [IN] the cmac result buffer
 *
 * @retval TEE_SUCCESS CMAC derive key success
 * @retval TEE_ERROR_NOT_SUPPORTED TEE not support this operation
 */
TEE_Result engine_power_on(void);
TEE_Result engine_power_off(void);
TEE_Result tee_ext_kdf_func(struct kdf_params_t *params, uint32_t hash_mode, uint32_t kdf_mode);
bool eps_support_cdrm_enhance(void);
TEE_Result do_eps_ctrl(uint32_t type, uint32_t profile);

#endif
