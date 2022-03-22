/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: keymaster attestation header
 * Create: 2017-05-14
 */
#ifndef __KM_ATTEST_H
#define __KM_ATTEST_H

#include "tee_internal_api.h"
#include "keymaster_defs.h"
#include "crypto_wrapper.h"
#include <dlist.h>
#include "tee_internal_api.h"
#include "keymaster_defs.h"
#include "km_attest_factory.h"
#include "km_types.h"

/* brand + device + product + manufacturer + model + SN + MEID + IMEI*5 */
#define ID_IDENTIFIERS_MAX     12
#define PROPERTY_VALUE_MAX     92
#define HMAC_SHA256_SIZE       32
#define IMEI_MAX               5
#define ID_IDENTIFIERS_VERSION 100

#define EC_PRIVKEY_INDEX   0U
#define EC_CERT_INDEX      1U
#define RSA_PRIVKEY_INDEX  2U
#define RSA_CERT_INDEX     3U

#define FILE_NAME_LEN_MAX 256
#define FILE_SIZE_MAX     (64 * 1024 * 1024)
/* come from CA */
struct identifiers_str {
    keymaster_tag_t tag;            /* keymaster TAG */
    char value[PROPERTY_VALUE_MAX]; /* string */
};

typedef struct {
    keymaster_tag_t tag;
    uint8_t hmac[HMAC_SHA256_SIZE];
} identifiers_hmac;

typedef struct {
    uint32_t version;
    uint8_t hmac[HMAC_SHA256_SIZE];
    identifiers_hmac id[ID_IDENTIFIERS_MAX];
} identifiers_stored;

uint32_t attestationids_len(const keymaster_key_param_set_t *attest_params);

TEE_Result verify_identifiers_with_param(const keymaster_key_param_set_t *attest_params);

TEE_Result generate_identifiers(const uint8_t *buf, identifiers_stored *id);
TEE_Result store_identifiers(const identifiers_stored *identifiers);
TEE_Result destroy_identifiers(void);
TEE_Result verify_identifiers(const identifiers_stored *identifiers);

int32_t decode_tlv(uint8_t *buf, uint32_t len, void *format, int32_t in_type);
void free_all(struct dev_key_t **dev_key, uint8_t **decrypt_buf, uint32_t en_len);
TEE_Result check_and_store_keybox(keymaster_blob_t *decrypt_buf, struct dev_key_t *dev_key,
    keymaster_blob_t *text_signed, const keymaster_blob_t *text_to_sign, TEE_Param *params,
    uint32_t chain_len, uint8_t *chain);

TEE_Result get_iv(uint8_t *iv_at, uint32_t kb_len, const uint8_t *kb_buf);
TEE_Result compare_files_and_sign_digest(const struct verify_info *v_info, uint32_t *text_signed_len,
    uint8_t *text_to_sign, uint8_t *text_signed, uint32_t text_to_sign_len);
TEE_Result do_attest_key(TEE_Param *params, keymaster_blob_t *app_id);
void build_authlist(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t len,
    uint8_t *extend_bufer_in);
identifiers_stored *read_identifiers(void);
int32_t km_store_devkey(const struct dev_key_t *dev_key);
#endif
