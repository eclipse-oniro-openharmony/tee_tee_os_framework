/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: keymaster attest factory header
 * Create: 2012-01-17
 */

#ifndef __KM_ATTEST_FACTORY_H
#define __KM_ATTEST_FACTORY_H

#include <dlist.h>
#include "tee_internal_api.h"
#include "hw_auth_token.h"
#include "keymaster_defs.h"
#include "crypto_wrapper.h"
#include "keyblob.h"

typedef struct {
    uint32_t count;
    uint32_t enumerated[KM_REP_MAX];
} auth_list_rep_param_t;

typedef struct {
    uint32_t count;
    keymaster_blob_t blob[KM_REP_MAX];
} auth_list_rep_blob;

typedef struct {
    bool tag_set; /* tag set or not */
    union {
        uint32_t enumerated;   /* KM_ENUM and KM_ENUM_REP */
        bool boolean;          /* KM_BOOL */
        uint32_t integer;      /* KM_INT and KM_INT_REP */
        uint64_t long_integer; /* KM_LONG */
        uint64_t date_time;    /* KM_DATE */
        keymaster_blob_t blob; /* KM_BIGNUM and KM_BYTES */
    };
} auth_list_param_t;

struct km_auth_list {
    auth_list_rep_param_t purpose;                  /* KM_ENUM_REP */
    auth_list_param_t algorithm;                    /* KM_ENUM */
    auth_list_param_t key_size;                     /* KM_INT */
    auth_list_rep_param_t digest;                   /* KM_ENUM_REP */
    auth_list_rep_param_t padding;                  /* KM_ENUM_REP */
    auth_list_param_t ec_curve;                     /* KM_ENUM */
    auth_list_param_t rsa_public_exponent;          /* KM_LONG */
    auth_list_param_t active_date_time;             /* KM_DATE */
    auth_list_param_t origination_expire_date_time; /* KM_DATE */
    auth_list_param_t usage_expire_date_time;       /* KM_DATE */
    auth_list_param_t no_auth_required;             /* KM_BOOL */
    auth_list_param_t user_auth_type;               /* KM_ENUM */
    auth_list_param_t auth_timeout;                 /* KM_INT */
    auth_list_param_t allow_while_on_body;          /* KM_BOOL */
    auth_list_param_t all_applications;             /* KM_BOOL */
    auth_list_param_t application_id;               /* KM_BYTES */
    auth_list_param_t creation_date_time;           /* KM_DATE */
    auth_list_param_t origin;                       /* KM_ENUM */
    auth_list_param_t rollback_resistance;          /* KM_BOOL */
    auth_list_param_t rollback_resistant;           /* KM_BOOL */
    auth_list_param_t root_of_trust;                /* KM_ROOT_OF_TRUST */
    auth_list_param_t os_version;                   /* KM_INT */
    auth_list_param_t patch_level;                  /* KM_INT */
    auth_list_param_t attestation_app_id;
    auth_list_param_t attestation_id_brand;
    auth_list_param_t attestation_id_device;
    auth_list_param_t attestation_id_product;
    auth_list_param_t attestation_id_serial;
    auth_list_rep_blob attestation_id_imei;
    auth_list_param_t attestation_id_meid;
    auth_list_param_t attestation_id_manufacturer;
    auth_list_param_t attestation_id_model;
};

#define SW_ENFORCED 0
#define HW_ENFORCED 1

typedef struct km_key_description {
    uint32_t attestation_version;
    keymaster_security_level_t attestation_security_level;
    uint32_t keymaster_version;
    keymaster_security_level_t keymaster_security_level;
    keymaster_blob_t attestation_challenge;
    keymaster_blob_t unique_id;
    keymaster_blob_t sw_enforced; /* KM_AUTH_LIST */
    keymaster_blob_t hw_enforced; /* KM_AUTH_LIST */
} km_key_description_t;

struct km_attest_key_element {
    uint8_t *attest_cert;
    uint32_t attest_cert_len;
    uint8_t *issuer_tlv;
    int32_t issuer_tlv_len;
    uint8_t pubkey_der[PUBKEY_DER_LEN];
    int32_t pubkey_len;
    uint8_t *attestation_ext;
    uint32_t attestation_ext_len;
    void *attest_key;
    uint32_t attest_key_len;
    int32_t attest_key_type;
    uint32_t sign_bit;
    uint32_t encrypt_bit;
    int32_t sw_key_type;
};

void free_attest(struct km_attest_key_element *ele);
void release_batch_cert(keymaster_blob_t *cert_entry);

int32_t build_attestation_extension(const keymaster_key_param_set_t *attest_params,
    const keymaster_key_param_set_t *authorizations, uint8_t *attestation_ext, uint32_t *attestation_ext_len);

int32_t get_attest_validity(validity_period_t *valid, const keymaster_key_param_set_t *authorizations,
    keymaster_blob_t *batch_cert);
/* format a chain buffer out formate with:"entry_count||cert_len||cert_context||cert_len||cert_context" */
int32_t format_provision_chain(uint8_t *chain, uint32_t *out_len, int32_t src, int32_t alg);

/* get file name of private key or cert. */
int32_t get_file_name(keymaster_blob_t *out_name, int32_t src, int32_t alg, int32_t file_type, int32_t cert_num);

/* get attest key(EC/RSA) */
int32_t get_attest_key(int src, int32_t alg, void *prv_key);

#endif
