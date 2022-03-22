/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster attest key process
 * Create: 2020-11-09
 */

#include "keymaster_defs.h"
#include "securec.h"
#include "keyblob.h"
#include "km_crypto.h"
#include "km_common.h"
#include "km_attest.h"
#include "km_attest_check.h"
#include "km_key_check.h"
#include "km_attest_default_certs.h"
#include "km_tag_operation.h"
#include "km_key_check.h"
#include "km_auth.h"
#include "km_env.h"
#include "km_types.h"
#include "km_key_gp_sw_convert.h"
#include "km_key_params.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#include "km_key_enhanced.h"
#endif
bool g_attest_key_provisioned = true;

static TEE_Result ec_get_pub_decrypt_keymaterial(keymaster_blob_t *keymaterial_blob, ecc_pub_key_t *sw_pubkey_ec,
    uint32_t version, const struct kb_crypto_factors *factors, uint32_t key_size)
{
    struct keymaterial_ecdsa_header *header = (struct keymaterial_ecdsa_header *)keymaterial_blob->data_addr;
    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    /* decrypt keymaterial */
    keymaster_blob_t encrypted_key = { header->key, header->key_buff_len };
    keymaster_blob_t decrypted_key = { NULL, header->key_buff_len };
    decrypted_key.data_addr = (uint8_t *)TEE_Malloc(header->key_buff_len, TEE_MALLOC_FILL_ZERO);
    if (decrypted_key.data_addr == NULL) {
        tloge("buf malloc failed, size %u\n", header->key_buff_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { header->iv, IV_LEN },
        *factors
    };
    TEE_Result ret = keyblob_crypto(&encrypted_key, &decrypted_key, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("decrypt keymaterial failed, ret = 0x%x\n", ret);
        goto release;
    }
    ret = init_key_obj(KM_ALGORITHM_EC, KM_DIGEST_NONE, key_size, &key_obj, &decrypted_key);
    if (ret != TEE_SUCCESS) {
        tloge("failed to allocate and init key object\n");
        goto release;
    }

    ret = convert_ec_gp2sw_key(key_obj, sw_pubkey_ec);
    if (ret != TEE_SUCCESS)
        tloge("key format transfer failed\n");
release:
    erase_free_blob(&decrypted_key);
    TEE_FreeTransientObject(key_obj);
    key_obj = TEE_HANDLE_NULL;
    return ret;
}

static TEE_Result ec_get_pub(keymaster_blob_t *keymaterial_blob, ecc_pub_key_t *sw_pubkey_ec, uint32_t version,
    const struct kb_crypto_factors *factors, uint32_t key_size)
{
    bool condition_check = (keymaterial_blob == NULL || keymaterial_blob->data_addr == NULL ||
        sw_pubkey_ec == NULL || factors == NULL);
    if (condition_check) {
        tloge("parameters null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (check_ec_keymaterial_header(keymaterial_blob) != TEE_SUCCESS) {
        tloge("bad keymaterial\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return ec_get_pub_decrypt_keymaterial(keymaterial_blob, sw_pubkey_ec, version, factors, key_size);
}

static TEE_Result key_blob_preproc(keyblob_head *keyblob, uint32_t keyblob_size, keymaster_blob_t *application_id)
{
    uint8_t hmac_result[HMAC_SIZE] = { 0 };
    int adaptable = 0;
    uint8_t *p = (uint8_t *)keyblob;
    /*
     * calculate HMAC After LOCK_ORANGE was made to generate the same key with LOCK_GREEN,
     * to adapt old version, we'll check again with an adaptable color
     * after first check failed.
     */
    TEE_Result ret = calculate_hmac(p, keyblob_size, hmac_result, &adaptable, keyblob, application_id);
    if (ret != TEE_SUCCESS) {
        tloge("keyblob hmac not match");
        return ret;
    }

    struct kb_crypto_factors factors = { *application_id, { NULL, 0 } };

    return decrypt_keyblob_hidden(keyblob, &factors);
}

/* Get device cert of attestation */
static int32_t get_batch_cert(int src, int alg, keymaster_blob_t *cert_entry)
{
    if (cert_entry == NULL) {
        tloge("cert entry is null\n");
        return -1;
    }

    /* get device cert */
    if (g_attest_key_provisioned == true)
        return get_cert_entry(src, alg, 0, cert_entry);
    /* huawei branch not support for now */
    if (src == SRC_HUAWEI) {
        tloge("no huawei untrusted cert support\n");
        return -1;
    }
    if (src != SRC_GOOGLE) {
        tloge("invalid src\n");
        return -1;
    }
    /* return google untrusted device cert */
    return device_cert(alg, cert_entry);
}
static int32_t copy_attest_cert(uint8_t **buff, uint32_t *left_len, uint32_t *fill_length,
    const uint8_t *attest_cert, uint32_t attest_cert_len)
{
    bool check_fail = (buff == NULL || *buff == NULL || left_len == NULL || fill_length == NULL || attest_cert == NULL);
    /* first copy attest cert */
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    if (*left_len < sizeof(uint32_t)) {
        tloge("buffer overflow, buff len %u\n", *left_len);
        return -1;
    }
    uint8_t *tmp = *buff;
    /* first copy attest cert */
    *(uint32_t *)tmp = attest_cert_len;
    tmp += sizeof(uint32_t);
    *fill_length = sizeof(uint32_t);
    errno_t rc = memcpy_s(tmp, *left_len - sizeof(uint32_t), attest_cert, attest_cert_len);
    if (rc != EOK) {
        tloge("[error]memcpy_s failed, rc=%d, line:%d\n", rc, __LINE__);
        return -1;
    }
    *fill_length += attest_cert_len;
    if (*left_len < *fill_length) {
        tloge("remained buffer is too short\n");
        return -1;
    }
    *buff += *fill_length;
    *left_len -= *fill_length;
    return 0;
}
static int32_t format_chain(uint8_t *chain, uint32_t *out_len, int32_t src, int32_t alg)
{
    int32_t ret;
    tlogd("provision chain len %u\n", *out_len);
    /* second copy dev and root cert */
    if (g_attest_key_provisioned == true) {
        ret = format_provision_chain(chain, out_len, src, alg);
        if (ret != 0) {
            tloge("format_provision_chain error:%d\n", ret);
            return ret;
        }
    } else {
        ret = format_untrusted_chain(chain, out_len, src, alg);
        if (ret != 0)
            tloge("format_untrusted_chain error:%d\n", ret);
    }
    tlogd("provision chain len %u\n", *out_len);
    return ret;
}

static int32_t format_attest_chain(uint8_t *chain, uint32_t *buff_len, const uint8_t *attest_cert,
    uint32_t attest_cert_len, int32_t src, int32_t alg)
{
    bool check = (chain == NULL) || (buff_len == NULL) || (attest_cert == NULL) || (attest_cert_len == 0) ||
                 (*buff_len < sizeof(uint32_t));
    if (check) {
        tloge("input is null!\n");
        return -1;
    }
    int32_t ret;
    uint8_t *tmp = chain;

    /* format chain body; */
    tmp += sizeof(uint32_t);
    uint32_t chain_len_out = sizeof(uint32_t);
    uint32_t tmp_buf_len = *buff_len - sizeof(uint32_t);
    uint32_t fill_length = 0;
    /* first copy attest cert */
    if (copy_attest_cert(&tmp, &tmp_buf_len, &fill_length, attest_cert, attest_cert_len) != 0) {
        tloge("copy attest cert failed\n");
        return -1;
    }
    chain_len_out += fill_length;

    /* fill the provision cert chain, and set the real length */
    ret = format_chain(tmp, &tmp_buf_len, src, alg);
    if (ret != 0) {
        tloge("format chain failed\n");
        return ret;
    }
    *(uint32_t *)chain = *(uint32_t *)tmp + 1; /* add attest cert */
    chain_len_out += tmp_buf_len - sizeof(uint32_t);

    /* del provison chain len bytes */
    if (memmove_s(tmp, tmp_buf_len, tmp + sizeof(uint32_t), (tmp_buf_len - sizeof(uint32_t))) != EOK) {
        tloge("[error]memmove_s failed\n");
        return -1;
    }
    *buff_len = chain_len_out;
    tlogd("format attest chain success, certcount=%u, outlen=%u\n", *(uint32_t *)chain, chain_len_out);
    return 0;
}

static TEE_Result get_algorithm_key_size(keymaster_algorithm_t *algorithm, uint32_t *key_size_bits,
    uint8_t *key_blob, uint32_t keyblob_size)
{
    bool check_fail = (key_blob == NULL || algorithm == NULL || key_size_bits == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (keyblob_size < sizeof(keyblob_head)) {
        tloge("bad keyblob size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    keyblob_head *keyblob = (keyblob_head *)key_blob;
    keymaster_key_param_set_t *param_enforced = (keymaster_key_param_set_t *)((uint8_t *)keyblob +
        keyblob->hw_enforced_offset);
    /* get algorithm from input param_enforced */
    TEE_Result ret = get_alg_keysize_from_paramsets(algorithm, key_size_bits, param_enforced);
    if (ret != TEE_SUCCESS) {
        tloge("get algorithm and keysize from keyblob paramset failed\n");
        return ret;
    }
    return TEE_SUCCESS;
}

static TEE_Result export_rsa_pubkey_to_attest(const keymaster_blob_t *keymaterial_blob, const keyblob_head *keyblob,
    const keymaster_blob_t *application_id, uint32_t key_size, keymaster_blob_t *pub_key_derformat)
{
    rsa_pub_key_t sw_pubkey_rsa;
    errno_t rc = memset_s(&sw_pubkey_rsa, sizeof(rsa_pub_key_t), 0, sizeof(rsa_pub_key_t));
    if (rc != EOK) {
        tloge("init sw rsa pub failed\n");
        return TEE_ERROR_GENERIC;
    }
    struct kb_crypto_factors factors = { *application_id, { NULL, 0 } };
    TEE_Result tee_ret = rsa_get_pub(keymaterial_blob, &sw_pubkey_rsa, keyblob->version, &factors, key_size);
    if (tee_ret != TEE_SUCCESS) {
        tloge("get rsa pub key failed\n");
        return tee_ret;
    }
    pub_key_derformat->data_length = (uint32_t)rsa_export_pub_sp(pub_key_derformat->data_addr,
        pub_key_derformat->data_length, &sw_pubkey_rsa);
    if (pub_key_derformat->data_length <= 0) {
        tloge("rsa_export_pub_sp error\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result export_ec_pubkey_to_attest(keymaster_blob_t *keymaterial_blob, keyblob_head *keyblob,
    const keymaster_blob_t *application_id, uint32_t key_size, keymaster_blob_t *pub_key_derformat)
{
    ecc_pub_key_t sw_pubkey_ec;
    errno_t rc = memset_s(&sw_pubkey_ec, sizeof(sw_pubkey_ec), 0, sizeof(sw_pubkey_ec));
    if (rc != EOK) {
        tloge("init sw ec pub failed\n");
        return TEE_ERROR_GENERIC;
    }
    struct kb_crypto_factors factors = { *application_id, { NULL, 0 } };
    TEE_Result tee_ret = ec_get_pub(keymaterial_blob, &sw_pubkey_ec, keyblob->version, &factors, key_size);
    if (tee_ret != TEE_SUCCESS) {
        tloge("get ec pub key failed\n");
        return tee_ret;
    }
    pub_key_derformat->data_length = (uint32_t)ecc_export_pub(pub_key_derformat->data_addr,
        pub_key_derformat->data_length, &sw_pubkey_ec);
    if (pub_key_derformat->data_length <= 0) {
        tloge("ecc_export_pub error\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
static TEE_Result km_attest_get_pub_key_check(const keyblob_head *key_to_attest,
    const keymaster_key_param_set_t *attest_params)
{
    if (key_to_attest->version == VERSION_340 || key_to_attest->version == VERSION_540 ||
        key_to_attest->version == VERSION_341 || key_to_attest->version == VERSION_541) {
        tloge("this keyblob version %u is not supported\n", key_to_attest->version);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    TEE_Result ret = unsupport_enhanced_key((const keymaster_key_param_set_t *)attest_params);
    if (ret != TEE_SUCCESS) {
        tloge("check unsupported tags failed\n");
        return ret;
    }

    return TEE_SUCCESS;
}
#endif

static TEE_Result km_attest_get_pub_key(TEE_Param *params, keymaster_algorithm_t *algorithm, uint8_t *pubkey_der,
    int32_t *pubkey_len, keymaster_blob_t *application_id)
{
    keymaster_key_param_set_t *attest_params = (keymaster_key_param_set_t *)params[1].memref.buffer;
    keyblob_head *key_to_attest = (keyblob_head *)params[0].memref.buffer;

    TEE_Result ret;
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    ret = km_attest_get_pub_key_check(key_to_attest, attest_params);
    if (ret != TEE_SUCCESS) {
        tloge("km attest get pub_key check failed\n");
        return ret;
    }
#endif
    ret = verify_identifiers_with_param(attest_params);
    if (ret != TEE_SUCCESS) {
        tloge("verify_identifiers_with_param failed, ret 0x%x\n", ret);
        return (TEE_Result)KM_ERROR_CANNOT_ATTEST_IDS;
    }
    /* export key_to_attest pubkey out */
    uint32_t key_size_in_bit = 0;
    keymaster_blob_t keymaterial_blob = { (uint8_t *)key_to_attest + key_to_attest->keymaterial_offset,
        key_to_attest->keymaterial_size };

    ret = key_blob_preproc(key_to_attest, key_to_attest->keyblob_total_size, application_id);
    if (ret != TEE_SUCCESS) {
        tloge("preprocess key blob is error\n");
        return ret;
    }

    /* verify APPLICATION_ID and APPLICATION_DATA ,error return KM_ERROR_INVALID_KEY_BLOB, required by google in v1 */
    if (authentication_key(key_to_attest, attest_params) != 0) {
        tloge("verify APPLICATION_ID and APPLICATION_DATA failed\n");
        return (TEE_Result)KM_ERROR_INVALID_KEY_BLOB;
    }
    ret = get_algorithm_key_size(algorithm, &key_size_in_bit, (uint8_t *)key_to_attest, params[0].memref.size);
    if (ret != TEE_SUCCESS) {
        tloge("get algorithm and keysize failed\n");
        return ret;
    }
    keymaster_blob_t pub_key_derformat = { pubkey_der, *pubkey_len };
    if (*algorithm == KM_ALGORITHM_RSA) {
        ret = export_rsa_pubkey_to_attest(&keymaterial_blob, key_to_attest, application_id, key_size_in_bit,
            &pub_key_derformat);
    } else if (*algorithm == KM_ALGORITHM_EC) {
        ret = export_ec_pubkey_to_attest(&keymaterial_blob, key_to_attest, application_id, key_size_in_bit,
            &pub_key_derformat);
    } else {
        tloge("key algorithm is invalid");
        return (TEE_Result)KM_ERROR_INCOMPATIBLE_ALGORITHM;
    }
    *pubkey_len = pub_key_derformat.data_length;
    if (ret != TEE_SUCCESS)
        tloge("export key to attest failed\n");
    return ret;
}

static TEE_Result km_attest_alloc_new_authorizations(const keyblob_head *key_to_attest,
    keymaster_key_param_set_t **authorizations_new)
{
    uint8_t *authorizations = (uint8_t *)key_to_attest + ((keyblob_head *)key_to_attest)->hw_enforced_offset;
    uint32_t new_params_len =
        key_to_attest->extend1_buf_offset - key_to_attest->hw_enforced_offset + key_to_attest->extend1_size;
    bool int_check = (new_params_len > (key_to_attest->extend1_buf_offset + key_to_attest->extend1_size) ||
        (key_to_attest->extend1_buf_offset + key_to_attest->extend1_size) < key_to_attest->extend1_size);
    if (int_check) {
        tloge("length, offset check failed\n");
        return TEE_ERROR_GENERIC;
    }
    uint8_t *new_params = (uint8_t *)TEE_Malloc(new_params_len, 0);
    if (new_params == NULL) {
        tloge("new_params malloc %u failed\n", new_params_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    int32_t ret = resort_key_characteristics((uint8_t *)new_params, (uint8_t *)authorizations, new_params_len);
    if (ret != 0) {
        tloge("resort key characteristics failed\n");
        TEE_Free(new_params);
        new_params = NULL;
        return TEE_ERROR_GENERIC;
    }
    *authorizations_new = (keymaster_key_param_set_t *)new_params;
    return TEE_SUCCESS;
}

static void init_ec_attest_param(uint32_t *attest_key_len, int32_t *attest_key_type, int32_t *sw_key_type)
{
    bool check_fail = (attest_key_len == NULL || attest_key_type == NULL || sw_key_type == NULL);
    if (check_fail) {
        tloge("null pointer");
        return;
    }
    *sw_key_type = ECC_ALG;
    *attest_key_type = ALG_EC;
    *attest_key_len = sizeof(ecc_priv_key_t);
    return;
}

static void init_rsa_attest_param(uint32_t *attest_key_len, int32_t *attest_key_type, int32_t *sw_key_type)
{
    bool check_fail = (attest_key_len == NULL || attest_key_type == NULL || sw_key_type == NULL);
    if (check_fail) {
        tloge("null pointer");
        return;
    }
    *sw_key_type = RSA_ALG;
    *attest_key_type = ALG_RSA;
    *attest_key_len = sizeof(rsa_priv_key_t);
    return;
}

static TEE_Result get_key_type(keymaster_algorithm_t algorithm,
    void **attest_key, int32_t *attest_key_type)
{
    if (set_file_operation() != TEE_SUCCESS) {
        tloge("set_file_operation failed\n");
        return TEE_ERROR_GENERIC;
    }
    file_operations_t *file_ops = get_file_operation_info();
    TEE_Result ret = (TEE_Result)get_attest_key(SRC_GOOGLE, *attest_key_type, *attest_key);
    bool condition = (((file_ops->fs_using == STORE_SFS) && (ret == TEE_ERROR_ITEM_NOT_FOUND)) ||
        ((file_ops->fs_using == STORE_RPMB) && (ret == TEE_ERROR_RPMB_FILE_NOT_FOUND)));
    if (condition) {
        /* when no found provision key, use default untrusted key */
        g_attest_key_provisioned = false;
        if (get_default_attest_key(algorithm, *attest_key) < 0) {
            tloge("get default attest fail");
            return TEE_ERROR_GENERIC;
        }
        ret = TEE_SUCCESS;
    } else if (ret != TEE_SUCCESS) {
        tloge("get attest key error ret=0x%x\n", ret);
    }
    return ret;
}
static TEE_Result km_attest_alloc_priv_key_and_get_key_type(keymaster_algorithm_t algorithm,
    void **attest_key, uint32_t *attest_key_len, int32_t *attest_key_type, int32_t *sw_key_type)
{
    if (algorithm == KM_ALGORITHM_EC) {
        init_ec_attest_param(attest_key_len, attest_key_type, sw_key_type);
    } else if (algorithm == KM_ALGORITHM_RSA) {
        init_rsa_attest_param(attest_key_len, attest_key_type, sw_key_type);
    } else {
        tloge("invalid algorithm:%d\n", algorithm);
        return TEE_ERROR_GENERIC;
    }
    *attest_key = (void *)TEE_Malloc((*attest_key_len), TEE_MALLOC_FILL_ZERO);
    if (*attest_key == NULL) {
        tloge("attest key mem alloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    return get_key_type(algorithm, attest_key, attest_key_type);
}

static void km_attest_get_cert_and_ext_len(const keymaster_key_param_set_t *attest_params,
    uint32_t *attest_cert_len, uint32_t *attestation_ext_len)
{
    uint32_t app_id_len = 0;
    keymaster_blob_t app_id = { NULL, 0 };
    uint32_t attestation_app_id_len = 0;
    keymaster_blob_t attestation_app_id;
    uint32_t attestation_ids_len = attestationids_len(attest_params);
    int32_t ret = get_key_param(KM_TAG_APPLICATION_ID, &app_id, attest_params);
    if (ret == 0)
        app_id_len = app_id.data_length;

    ret = get_key_param(KM_TAG_ATTESTATION_APPLICATION_ID, &attestation_app_id, attest_params);
    if (ret == 0)
        attestation_app_id_len = attestation_app_id.data_length;

    *attest_cert_len = ATTEST_CERT_BUF_LEN + app_id_len + attestation_app_id_len + attestation_ids_len;
    *attestation_ext_len = ATTEST_EXT_BUF_LEN + app_id_len + attestation_app_id_len + attestation_ids_len;
}
static TEE_Result km_attest_get_batch_cert_and_purpose(uint32_t *sign_bit, uint32_t *encrypt_bit,
    int32_t attest_key_type, keymaster_blob_t *batch_cert, keymaster_key_param_set_t *authorizations)
{
    keymaster_purpose_t purpose_encrypt = KM_PURPOSE_ENCRYPT;
    keymaster_purpose_t purpose_decrypt = KM_PURPOSE_DECRYPT;
    keymaster_purpose_t purpose_sign = KM_PURPOSE_SIGN;
    keymaster_purpose_t purpose_verify = KM_PURPOSE_VERIFY;
    bool condition_check = ((is_key_param_suport(KM_TAG_PURPOSE, (void *)&purpose_sign, authorizations) != 0) ||
        (is_key_param_suport(KM_TAG_PURPOSE, (void *)&purpose_verify, authorizations) != 0));
    if (condition_check)
        *sign_bit = 1;
    condition_check = ((is_key_param_suport(KM_TAG_PURPOSE, (void *)&purpose_encrypt, authorizations) != 0) ||
        (is_key_param_suport(KM_TAG_PURPOSE, (void *)&purpose_decrypt, authorizations) != 0));
    if (condition_check)
        *encrypt_bit = 1;

    /* get batch cert */
    TEE_Result ret = (TEE_Result)get_batch_cert(SRC_GOOGLE, attest_key_type, batch_cert);
    if (ret != TEE_SUCCESS) {
        tloge("get device cert error:0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }
    return ret;
}
static TEE_Result build_attest_ext_and_key(struct km_attest_key_element *ele, keymaster_key_param_set_t *attest_params,
    keymaster_key_param_set_t *authorizations, keymaster_algorithm_t algorithm, keymaster_blob_t *batch_cert)
{
    /* caller function will free the heap buffer malloced by this function */
    TEE_Result ret;
    /* build attestation extension */
    ele->attestation_ext = (uint8_t *)TEE_Malloc(ele->attestation_ext_len, 0);
    if (ele->attestation_ext == NULL) {
        tloge("attestation_ext buf malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    ret = (TEE_Result)build_attestation_extension(attest_params, authorizations, ele->attestation_ext,
        &(ele->attestation_ext_len));
    if (ret != TEE_SUCCESS) {
        tloge("attestation_ext content failed\n");
        goto free_attest_ext;
    }

    /* 3.get attest private key */
    ret = km_attest_alloc_priv_key_and_get_key_type(algorithm, &ele->attest_key, &ele->attest_key_len,
        &ele->attest_key_type, &(ele->sw_key_type));
    if (ret != TEE_SUCCESS) {
        tloge("get attest private key failed\n");
        goto free_attest_ext;
    }
    /* 4.get purpose from input hw_enforced */
    ret = km_attest_get_batch_cert_and_purpose(&(ele->sign_bit), &(ele->encrypt_bit), ele->attest_key_type,
                                               batch_cert, authorizations);
    if (ret != TEE_SUCCESS) {
        tloge("get attest batch cert and pourpose failed\n");
        goto free_attest_ext;
    }
    return TEE_SUCCESS;
free_attest_ext:
    free_attest(ele);
    return ret;
}

static TEE_Result km_attest_get_time_and_issuer(keymaster_blob_t *batch_cert,
    keymaster_key_param_set_t *authorizations, validity_period_t *valid, uint8_t **issuer_tlv, int32_t *issuer_tlv_len)
{
    if (get_attest_validity(valid, authorizations, batch_cert) != 0) {
        tloge("attest cert validity get failed\n");
        return TEE_ERROR_GENERIC;
    }
    /* get issuer */
    *issuer_tlv_len = get_tbs_element(issuer_tlv, TLV_NUM_FIVE, batch_cert->data_addr, batch_cert->data_length);
    /* Use the subject field of the batch attestation key as issuer. */
    if (*issuer_tlv_len < 0) {
        tloge("issuer_tlv get failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result km_attest_fill_cert_element(TEE_Param *params, struct km_attest_key_element *ele,
    keymaster_blob_t *batch_cert, validity_period_t *valid, keymaster_blob_t *application_id)
{
    /* get pub key for der */
    ele->pubkey_len = PUBKEY_DER_LEN;
    keymaster_algorithm_t algorithm = 0;
    keyblob_head *key_to_attest = (keyblob_head *)params[0].memref.buffer;
    keymaster_key_param_set_t *attest_params = (keymaster_key_param_set_t *)params[1].memref.buffer;
    TEE_Result ret = km_attest_get_pub_key(params, &algorithm, ele->pubkey_der, &ele->pubkey_len, application_id);
    if (ret != TEE_SUCCESS) {
        tloge("get pub key for der failed\n");
        return ret;
    }
    /* authorizations can not free in this fun, it's contant will used in callder */
    keymaster_key_param_set_t *authorizations = NULL;
    ret = km_attest_alloc_new_authorizations(key_to_attest, &authorizations);
    if (ret != TEE_SUCCESS) {
        tloge("alloc new authorizations failed\n");
        return ret;
    }
    /* format x509 cert of attestation */
    km_attest_get_cert_and_ext_len(attest_params, &ele->attest_cert_len, &ele->attestation_ext_len);
    ele->attest_cert = (uint8_t *)TEE_Malloc(ele->attest_cert_len, 0);
    if (ele->attest_cert == NULL) {
        tloge("attest_cert buf malloc failed\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto free_auth;
    }

    ret = build_attest_ext_and_key(ele, attest_params, authorizations, algorithm, batch_cert);
    if (ret != TEE_SUCCESS) {
        tloge("build attest extend buffer and key failed\n");
        goto free_cert;
    }
    /* 5.get valid time period, get issuer */
    ret = km_attest_get_time_and_issuer(batch_cert, authorizations, valid, &ele->issuer_tlv, &ele->issuer_tlv_len);
    if (ret != TEE_SUCCESS) {
        tloge("get time and issuer failed\n");
        goto free_batch;
    }
    TEE_Free(authorizations);
    return ret;
free_batch:
    release_batch_cert(batch_cert);
free_cert:
    free_attest(ele);
free_auth:
    TEE_Free(authorizations);
    return ret;
}
TEE_Result do_attest_key(TEE_Param *params, keymaster_blob_t *app_id)
{
    int32_t e_ret;
    TEE_Result ret;
    keymaster_blob_t batch_cert = { 0 };
    validity_period_t valid;
    struct km_attest_key_element ele;

    if (memset_s(&ele, sizeof(ele), 0, sizeof(ele)) != EOK) {
        tloge("init attest key element failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (pthread_mutex_lock(get_attest_key_lock()) != TEE_SUCCESS) {
        tloge("lock g_attest_key_provisioned failed\n");
        return TEE_ERROR_GENERIC;
    }

    ret = km_attest_fill_cert_element(params, &ele, &batch_cert, &valid, app_id);
    if (ret != TEE_SUCCESS) {
        tloge("get attest key element fail\n");
        goto unlock;
    }

    e_ret = create_attestation_cert(ele.attest_cert, ele.attest_cert_len, &valid, ele.issuer_tlv,
                                    (uint32_t)ele.issuer_tlv_len, ele.pubkey_der, (uint32_t)ele.pubkey_len,
                                    ele.attestation_ext, ele.attestation_ext_len, ele.attest_key,
                                    ele.sign_bit, ele.encrypt_bit, (uint32_t)ele.sw_key_type, SHA256_HASH);
    if (e_ret <= 0) {
        tloge("create_attestation_cert error\n");
        ret = TEE_ERROR_GENERIC;
        goto free_cert;
    }
    ele.attest_cert_len = (uint32_t)e_ret;

    /* format cert chain, chain info already checked in km_attest_key_check */
    uint8_t *cert_chain = params[PARAM_NBR_TWO].memref.buffer;
    uint32_t cert_chain_len = params[PARAM_NBR_TWO].memref.size;
    ret = (TEE_Result)format_attest_chain(cert_chain, &cert_chain_len, ele.attest_cert, ele.attest_cert_len,
        SRC_GOOGLE, ele.attest_key_type);
free_cert:
    free_attest(&ele);
    release_batch_cert(&batch_cert);
unlock:
    g_attest_key_provisioned = true;
    if (pthread_mutex_unlock(get_attest_key_lock()) != TEE_SUCCESS) {
        tloge("unlock g_attest_key_provisioned failed\n");
        return TEE_ERROR_GENERIC;
    }
    return ret;
}

/* Release device cert of attestation */
void release_batch_cert(keymaster_blob_t *cert_entry)
{
    if (cert_entry == NULL) {
        tloge("the cert_entry is null\n");
        return;
    }
    /* if g_attest_key_provisioned is true, cert_entry->data is malloced, otherwise is global array,no need free */
    bool condition = ((g_attest_key_provisioned == true) && (cert_entry->data_addr != NULL));
    if (condition)
        TEE_Free(cert_entry->data_addr);
    cert_entry->data_addr = NULL;
    cert_entry->data_length = 0;
}

void free_attest(struct km_attest_key_element *ele)
{
    if (ele == NULL)
        return;
    if (ele->attest_key != NULL) {
        if (memset_s(ele->attest_key, ele->attest_key_len, 0, ele->attest_key_len) != EOK)
            tloge("memset_s attest key failed");
        TEE_Free(ele->attest_key);
        ele->attest_key = NULL;
    }
    if (ele->attest_cert != NULL) {
        TEE_Free(ele->attest_cert);
        ele->attest_cert = NULL;
    }

    if (ele->attestation_ext != NULL) {
        TEE_Free(ele->attestation_ext);
        ele->attestation_ext = NULL;
    }
    if (memset_s(ele, sizeof(*ele), 0, sizeof(*ele)) != EOK)
        tloge("memset_s key element failed");
}
