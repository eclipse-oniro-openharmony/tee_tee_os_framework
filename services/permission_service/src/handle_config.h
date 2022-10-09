/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: permission handle config
 * Author: TianJianliang tianjianliang@huawei.com
 * Create: 2016-04-01
 */
#ifndef PERMISSION_SERVICE_HANDLE_CONFIG_H
#define PERMISSION_SERVICE_HANDLE_CONFIG_H

#include <tee_defines.h>
#include "permission_service.h"

#define ASN1_FORMAT_TIME_SIZE      13
#define ASN1_TO_INT(x)             ((x) - '0')
#define SHA256_LEN                 32   /* now use sha256 hash alg */
#define SHA512_LEN                 64
#define HASH_UPDATA_LEN            1024 /* modify from 64 to 1024, reduce elf-load time */
#define TA_CONFIG_SEGMENT_MAGIC    0xABCDABCD
#define TA_CONFIG_SEGMENT_VERSION  0x1
#define SN_MAX_SIZE                64
#define CONFIG_HEADER_V1           1
#define CONFIG_HEADER_V2           2
#define TYPE_PUB_KEY               0
#define TYPE_CERT                  1
#define TYPE_CERT_CHAIN            2
#define SIGN_TYPE_RSA_SHA256_PKCS1 1
#define SIGN_TYPE_ECDSA_SHA256     2
#define SIGN_TYPE_RSA_SHA256_PSS   3
#define CA_PUBLIC                  1
#define CA_PRIVATE                 2
#define SIGN_CONFIG_ALG_BITS       30
#define CONFIG_SIGNATURE_LEN_MASK  0x3FFFFFFF
#define CONFIG_SIGN_ALG_RSA_PKCS1  1
#define CONFIG_SIGN_ALG_RSA_PSS    2
#define CONFIG_SIGN_ALG_RSA_ECDSA  3

#define POLICY_VER_VALID_INDEX         0 /* this bits always is 1, check policy version is invalid */
#define POLICY_VER_XML2TLV_PARSE_INDEX 1 /* tool type for parse xml */
#define POLICY_VER_PRODUCT_INDEX       2 /* policy version for product */

#define BASE_POLICY_VERSION_TEE        0b001
#define BASE_POLICY_VERSION_OH         0b101

#define PRODUCT_BIT_MAP                (1 << POLICY_VER_PRODUCT_INDEX)
#define CONFIG_POLICY_OH               (BASE_POLICY_VERSION_OH & PRODUCT_BIT_MAP)

#define XML2TLV_JAR_VALUE              (0 << POLICY_VER_XML2TLV_PARSE_INDEX) /* jar parse xml */
#define XML2TLV_PY_VALUE               (1 << POLICY_VER_XML2TLV_PARSE_INDEX) /* python parse xml */

#define XML2TLV_PARSE_BIT_MAP          (1 << POLICY_VER_XML2TLV_PARSE_INDEX)

struct ta_identity {
    TEE_UUID uuid;
    uint8_t *service_name;
    uint32_t service_name_len;
};

#define V1_RESERVED_LEN 4
struct config_header_v1 {
    uint32_t magic_num;
    uint16_t version;
    uint16_t policy_version;
    uint32_t context_len;
    uint32_t ta_cert_len;
    uint32_t config_len;
    uint32_t signature_len;
    uint32_t config_cert_len;
    uint32_t reserved[V1_RESERVED_LEN];
};

#define V2_RESERVED_LEN 5
struct config_header_v2 {
    uint32_t magic_num;
    uint16_t version;
    uint16_t policy_version;
    uint32_t context_len;
    uint32_t ta_cert_len;
    uint32_t config_len;
    uint32_t config_verify_len;
    uint32_t reserved[V2_RESERVED_LEN];
};

union header_union {
    struct config_header_v1 v1;
    struct config_header_v2 v2;
};

struct config_header {
    uint32_t version;
    union header_union header;
};

struct secure_img_data {
    const uint8_t *cert;
    size_t cert_size;
    uint8_t *cn;
    uint32_t cn_size;
};

struct sign_verify_data {
    uint32_t type;
    uint32_t sign_alg;
    uint8_t *cert;
    uint32_t cert_len;
    uint8_t *signature;
    uint32_t signature_len;
};

struct ta_cert_info {
    uint32_t type;
    uint8_t *cert;
    uint32_t cert_len;
};

struct ta_package {
    const uint8_t *config_package;
    uint32_t package_size;
    const uint8_t *name;
    uint32_t name_len;
};

struct tlv_config {
    uint8_t *data;
    uint32_t len;
};

struct ta_config_info {
    struct config_header header;
    struct ta_cert_info ta_cert;
    struct tlv_config tlv_config;
    struct sign_verify_data verify_data;
};

uint32_t get_ca_pubkey_size(void);
uint32_t get_pub_ca_key_size(uint32_t alg);
uint32_t get_priv_ca_key_size(uint32_t alg);
const uint8_t *get_ca_pubkey(void);
const uint8_t *get_pub_ca_key(uint32_t alg);
const uint8_t *get_priv_ca_key(uint32_t alg);
const char *get_config_cert_cn(void);
const char *get_config_cert_ou_prod(void);
const char *get_oh_config_cert_cn(void);
const char *get_config_cert_ou_dev(void);
const char *get_oh_config_ou_prod(void);
const char *get_oh_config_ou_dev(void);
const rsa_pub_key_t *get_config_pub_key(void);
uint32_t get_ca_type(void);

TEE_Result cert_expiration_check(const uint8_t *cert, size_t cert_size);
TEE_Result ta_run_authorization_check(const TEE_UUID *uuid, const ta_property_t *manifest,
                                      uint16_t target_version, bool mem_page_align);
TEE_Result ta_conf_package_process(const TEE_UUID *uuid, const struct ta_package *package, cert_param_t *cert_param);
TEE_Result tee_secure_img_check_cert_validation(const uint8_t *cert, size_t cert_size, const uint8_t *parent_key,
                                                uint32_t parent_key_len);
TEE_Result tee_secure_img_parse_cert(rsa_pub_key_t *public_key, struct secure_img_data *data, uint8_t *ou,
                                     uint32_t *ou_size);
TEE_Result tee_secure_img_calc_hash(const uint8_t *hash_body, size_t hash_body_size, uint8_t *hash_result,
                                    size_t hash_result_size, uint32_t alg);
TEE_Result tee_secure_img_verify_signature(const uint8_t *signaure, size_t signaure_size, const uint8_t *hash_result,
                                           size_t hash_result_size, const rsa_pub_key_t *public_key);
TEE_Result tee_ext_set_config(const uint8_t *conf, uint32_t conf_len, const TEE_UUID *uuid, const uint8_t *service_name,
                              uint32_t service_name_len, void *cert_param);

#endif
