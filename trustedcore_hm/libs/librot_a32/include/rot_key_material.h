/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Root of Trust key material definition.
 * Author: t00360454
 * Create: 2020-02-11
 */
#ifndef _ROOT_OF_TRUST_KEY_MATERIAL_H_
#define _ROOT_OF_TRUST_KEY_MATERIAL_H_
#include <tee_internal_api.h>

/* key parameters of import key */
struct rot_key_params {
    uint32_t key_size;
    uint32_t key_type;
    uint32_t key_purpose;
    uint32_t key_padding;
    uint32_t key_mode;
    uint32_t origin;
    uint32_t key_len;
    uint8_t *key_material; /* key_len in bytes */
};

/* key blob handle */
#define BLOB_MAC_LENGTH 16
struct rot_key_blob {
    uint32_t key_size;
    uint32_t key_type;
    uint32_t key_purpose;
    uint32_t key_padding;
    uint32_t key_mode;
    uint32_t key_origin;
    uint32_t cert_exist;
    uint32_t cert_location;
    uint32_t cert_size;
    uint32_t key_len;
    uint8_t *key_material; /* key_len in bytes */
    uint8_t mac[BLOB_MAC_LENGTH];
};

/* the key type definition of key material */
enum kmat_key_type {
    TYPE_AES = 0x00020000,
    TYPE_SM4 = 0x00030000,
    TYPE_RSA = 0x00040000,
    TYPE_ECC = 0x00050000,
    TYPE_SM2 = 0x00060000,
    TYPE_HMAC = 0x00070000
};

/* the key purpose definition of key material */
enum kmat_key_purpose {
    PURPOSE_SIGN = 1,
    PURPOSE_VERIFY = 2,
    PURPOSE_ENC = 4,
    PURPOSE_DEC = 8,
    PURPOSE_MAC = 16
};

/* the key padding definition of key material */
enum kmat_key_padding {
    PAD_NOPAD = 0x00000001,
    PAD_ISO9797_M1 = 0x00000002,
    PAD_ISO9797_M2 = 0x00000004,
    PAD_PKCS5 = 0x00000008  /* The same as PKCS7 */
};

/* the key mode definition of key material */
enum kmat_key_mode {
    /* signature */
    MODE_RSASSA_PKCS1_V1_5_SHA1 = 0x00000001,
    MODE_RSASSA_PKCS1_V1_5_SHA224 = 0x00000002,
    MODE_RSASSA_PKCS1_V1_5_SHA256 = 0x00000004,
    MODE_RSASSA_PKCS1_PSS_SHA1 = 0x00000010,
    MODE_RSASSA_PKCS1_PSS_SHA224 = 0x00000020,
    MODE_RSASSA_PKCS1_PSS_SHA256 = 0x00000040,
    MODE_ECDSA_SHA256 = 0x00000100,

    /* asymmetric cipher */
    MODE_RSAES_NOPAD = 0x00010000,
    MODE_RSAES_PKCS1_V1_5 = 0x00020000,
    MODE_RSAES_PKCS1_OAEP_SHA1 = 0x00040000,
    MODE_RSAES_PKCS1_OAEP_SHA224 = 0x00080000,
    MODE_RSAES_PKCS1_OAEP_SHA256 = 0x00100000,
    MODE_SM2ES_NOPAD = 0x01000000,

    /* symmetric cipher */
    MODE_CBC = 0x02000000,

    /* MAC */
    MODE_CBC_MAC = 0x04000000,
    MODE_CMAC = 0x08000000,
};

/* the key origin definition of key material */
enum kmat_key_origin {
    KEY_ORIGIN_IMPORT = 0x01,
    KEY_ORIGIN_GEN,
};

/* cert exist status definition */
enum cert_status {
    CERT_EXIST = 0x00,
    CERT_NON_EXISTENT = 0x01,
};

/* the tag definition of device ids */
enum msp_ids_tag {
    TAG_IDS_BRAND = 1,
    TAG_IDS_DEVICE = 2,
    TAG_IDS_PRODUCT = 3,
    TAG_IDS_SERIAL = 4,
    TAG_IDS_MEID = 5,
    TAG_IDS_MANUFACTURER = 6,
    TAG_IDS_MODEL = 7,
    TAG_IDS_IMEI = 8,
};

/* the tag definition of AuthorizationList */
enum msp_auth_list_tag {
    /* Base info */
    TAG_ATK_BASE_VERSION = 0,
    TAG_ATK_BASE_SN = 1,
    TAG_ATK_BASE_SIGNATURE = 2,
    TAG_ATK_BASE_ISSUER = 3,
    TAG_ATK_BASE_VALIDITY = 4,
    TAG_ATK_BASE_SUBJECT = 5,
    TAG_ATK_BASE_SUBJECT_PUB_KEY = 6,
    /* Ext info */
    TAG_ATK_EXT_KEY_USAGE = 7,
    TAG_ATK_EXT_CRL_POINTS = 8,
    TAG_ATK_EXT_ATTESTATION_VERSION = 9,
    TAG_ATK_EXT_ATTESTATION_SECURITY_LEVEL = 10,
    TAG_ATK_EXT_VERSION = 11,
    TAG_ATK_EXT_SECURITY_LEVEL = 12,
    TAG_ATK_EXT_ATTESTATION_CHALLENGE = 13,
    TAG_ATK_EXT_UNIQUEID = 14,
    TAG_ATK_EXT_AUTHORIZATION_LIST = 15,
    /* Crypto parameters */
    TAG_ATK_PURPOSE = 16,
    TAG_ATK_ALGORITHM = 17,
    TAG_ATK_KEY_SIZE = 18,
    TAG_ATK_BLOCK_MODE = 19,
    TAG_ATK_DIGEST = 20,
    TAG_ATK_PADDING = 21,
    TAG_ATK_EC_CURVE = 22,
    /* Algorithm-specific. */
    TAG_ATK_RSA_PUBLIC_EXPONENT = 23,
    TAG_ATK_ROLLBACK_RESISTANCE = 24,
    /* Key validity period */
    TAG_ATK_ACTIVE_DATETIME = 25,
    TAG_ATK_ORIGINATION_EXPIRE_DATETIME = 26,
    /* Date when existing "messages" should no longer be trusted. */
    TAG_ATK_USAGE_EXPIRE_DATETIME = 27,
    TAG_ATK_NO_AUTH_REQUIRED = 28,
    TAG_ATK_USER_AUTH_TYPE = 29,
    TAG_ATK_AUTH_TIMEOUT = 30,
    TAG_ATK_ALLOW_WHILE_ON_BODY = 31,
    TAG_ATK_TRUSTED_USER_PRESENCE_REQUIRED = 32,
    TAG_ATK_TRUSTED_CONFIRMATION_REQUIRED = 33,
    TAG_ATK_UNLOCKED_DEVICE_REQUIRED = 34,
    TAG_ATK_ALL_APPLICATIONS = 35,
    TAG_ATK_APPLICATION_ID = 36,
    TAG_ATK_CREATION_DATETIME = 37,
    TAG_ATK_ORIGIN = 38,
    TAG_ATK_ROLLBACK_RESISTANT = 39,
    TAG_ATK_ROOT_OF_TRUST = 40,
    TAG_ATK_OS_VERSION = 41,
    TAG_ATK_OS_PATCHLEVEL = 42,
    TAG_ATK_UNIQUE_ID = 43,
    TAG_ATK_ATTESTATION_CHALLENGE = 44,
    TAG_ATK_ATTESTATION_APPLICATION_ID = 45,
    TAG_ATK_VENDOR_PATCHLEVEL = 58, /* skip 12 steps for IDs */
    TAG_ATK_BOOT_PATCHLEVEL = 59
};

#endif
