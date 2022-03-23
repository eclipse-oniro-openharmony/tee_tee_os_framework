/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster keyblob process header
 * Create: 2020-11-09
 */
#ifndef __KM_KEYBLOB_H
#define __KM_KEYBLOB_H
#include "tee_internal_api.h"
#include "km_types.h"

#define MIN_INSECURE_RSA_PUB_E 0x10001
struct keymaterial_rsa_header {
    uint32_t magic;
    uint8_t iv[IV_LEN];
    uint32_t key_buff_len;
    uint32_t crt_mode;
    uint8_t key[0];
};

struct keymaterial_ecdsa_header {
    uint32_t magic;
    uint8_t iv[IV_LEN];
    uint32_t key_buff_len;
    uint32_t ecc_curv;
    uint8_t key[0];
};

struct keymaterial_symmetric_header {
    uint32_t magic;
    uint8_t iv[IV_LEN];
    uint32_t key_buff_len;
    uint8_t key[0]; /* HMAC key allow any length key */
};

typedef struct {
    uint8_t key[DES_ONE_KEY_LEN];
} keymaster_des_single_key_t;

/*
 * keyblob:| -- keyblob_head --|-- keymaterial --
 * |--hw_enforced--|-- params[] --|-- sw_enforced --|-- params[] --|-- extend buffer --
 * |--hidden--|--extend--buffer--|
 */
typedef struct {
    uint8_t hmac[HMAC_SIZE];
    uint8_t hidden_iv[IV_LEN];
    uint32_t magic;
    uint32_t version;
    uint32_t keymaterial_offset;
    uint32_t keymaterial_size;
    uint32_t hw_enforced_offset;
    uint32_t sw_enforced_offset;
    uint32_t extend1_buf_offset;
    uint32_t extend1_size;
    uint32_t hidden_offset;
    uint32_t extend2_buf_offset;
    uint32_t extend2_size;
    uint32_t keyblob_total_size;
} keyblob_head;

TEE_Result decrypt_keyblob_hidden(keyblob_head *key_blob, const struct kb_crypto_factors *factors);
int32_t generate_keyblob(const uint8_t *keymaterial, uint32_t keymaterial_size, keymaster_key_origin_t origin,
                         TEE_Param *params, uint32_t version);
TEE_Result keyblob_crypto(const keymaster_blob_t *data_in, keymaster_blob_t *data_out,
    const struct keyblob_crypto_ctx *ctx);
TEE_Result symm_key_dx2gp(keymaster_blob_t *dx_key, keymaster_blob_t *gp_key);
TEE_Result ecc_key_dx2gp(keymaster_blob_t *pub_key, keymaster_blob_t *pri_key, uint32_t *ec_cure,
    keymaster_blob_t *gp_key);
TEE_Result rsa_key_dx2gp(keymaster_blob_t *rsa_key, keymaster_blob_t *gp_key, uint32_t *is_crt);
TEE_Result rsa_key_sw2gp(keymaster_blob_t *rsa_key, keymaster_blob_t *gp_key, uint32_t *is_crt);
TEE_Result get_new_key_material(const void *keyblob_in, const struct kb_crypto_factors *factors,
    keymaster_blob_t *keyblob_out);
TEE_Result generate_symmetric_keymaterial(TEE_ObjectHandle object_handle, const struct kb_crypto_factors *factors,
    uint32_t version, keymaster_blob_t *keymaterial);
TEE_Result generate_ec_keymaterial(TEE_ObjectHandle object_handle, uint32_t gp_ec_curve, uint32_t version,
    const struct kb_crypto_factors *factors, keymaster_blob_t *keymaterial);
TEE_Result generate_rsa_keymaterial(TEE_ObjectHandle object_handle, uint32_t version,
    const struct kb_crypto_factors *factors, keymaster_blob_t *keymaterial);
TEE_Result parser_symmetric_keymaterial(uint8_t *input, uint8_t *output, uint32_t key_size, uint32_t version,
    const struct kb_crypto_factors *factors);

TEE_Result process_public_key_out(keymaster_algorithm_t algorithm, TEE_Param *params,
    const keymaster_key_param_set_t *hw_enforced, const struct kb_crypto_factors *factors);
TEE_Result generate_key(keymaster_algorithm_t algorithm, uint32_t key_size,
    const keymaster_key_param_set_t *params_hw_enforced, TEE_Param *params);

TEE_Result generate_unknown_keyblob(uint32_t version, TEE_Param *params, const uint8_t *keymaterial,
    uint32_t temp_size);
TEE_Result check_curve_value_with_type(TEE_ECC_CURVE *ecc_curv, const keymaster_key_param_set_t *params_hw_enforced,
    uint32_t key_size);
int32_t encrypt_keyblob_hidden(keymaster_key_param_set_t *hidden, keyblob_head *keyblob,
    const struct kb_crypto_factors *factors);

int check_symmetric_key_random(uint32_t key_size_in_bytes, const uint8_t *key);
TEE_Result import_rsa_key(TEE_Param *params, const keymaster_key_param_set_t *params_hw_enforced, uint32_t version);
TEE_Result import_ec_key(TEE_Param *params, const keymaster_key_param_set_t *params_hw_enforced, uint32_t version);
TEE_Result import_symmetric_key(TEE_Param *params, keymaster_algorithm_t algorithm,
    const keymaster_key_param_set_t *params_hw_enforced, uint32_t version);

TEE_Result km_upgrade_version_patch_level(TEE_Param *params, keyblob_head *keyblob_in,
    uint32_t keyblob_in_size, keyblob_head *keyblob_out, uint32_t *keyblob_out_size);
TEE_Result km_upgrade_end(TEE_Param *params, keyblob_head *keyblob_in,
    keyblob_head *keyblob_out, keymaster_blob_t *application_id);
TEE_Result km_copy_keyblob(keyblob_head *keyblob_in, uint32_t keyblob_in_size, const struct kb_crypto_factors *factors,
    keyblob_head *keyblob_out, uint32_t keyblob_out_size);
TEE_Result build_new_key_blob(const keyblob_head *keyblob_in, const keymaster_blob_t *new_material,
    keymaster_blob_t *keyblob_out);
#endif
