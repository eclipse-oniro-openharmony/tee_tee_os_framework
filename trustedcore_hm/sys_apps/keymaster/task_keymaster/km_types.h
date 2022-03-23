/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster tyes definition
 * Create: 2020-11-09
 */
#ifndef __KM_TYPES_H
#define __KM_TYPES_H
#include "keymaster_defs.h"
#include "tee_internal_api.h"
#include "km_defines.h"

enum at_tlv_node_type {
    ATTLVNODE_NONE = 0,
    ATTLVNODE_DEVKEY,
    ATTLVNODE_ALG,
    ATTLVNODE_DEVID,
    ATTLVNODE_SRC,
    ATTLVNODE_PRVKEY,
    ATTLVNODE_CERTS,
    ATTLVNODE_CERT_ENTRY,
    ATTLVNODE_HASH,
    ATTLVNODE_VB,
    ATTLVNODE_VB_INFO,
    ATTLVNODE_CERT_HASH
};

struct dev_key_t {
    int32_t alg;
    char *dev_id;
    int32_t src;
    keymaster_blob_t prv_key;
    keymaster_cert_chain_t chain;
    uint8_t hash[SHA256_LENGTH];
};

struct verify_info {
    int32_t alg;
    char *dev_id;
    int32_t src;
    uint8_t cert_hash[SHA256_LENGTH];
};

typedef struct {
    int32_t v_info_count;
    struct verify_info *v_info;
    uint8_t hash[SHA256_LENGTH];
} verify_table;

struct symmerit_key_t {
    uint32_t key_type;
    uint64_t key_buffer;
    uint32_t key_size;
};

struct ae_init_data {
    uint64_t nonce;
    uint32_t nonce_len;
    uint32_t tag_len;
    uint32_t aad_len;
    uint32_t payload_len;
};

struct rsa_params_alogrithm {
    keymaster_padding_t padding;
    keymaster_digest_t digest;
    uint32_t gp_algorithm;
};

struct session_identity {
    uint32_t len;
    char val[SESSION_ID_COUNT];
};

typedef enum {
    KM_RSA_MD5_PKCS1_5 = 1,
    KM_RSA_SHA1_PKCS1_5 = 2,
    KM_RSA_SHA224_PKCS1_5 = 3,
    KM_RSA_SHA256_PKCS1_5 = 4,
    KM_RSA_SHA384_PKCS1_5 = 5,
    KM_RSA_SHA512_PKCS1_5 = 6,
    KM_RSA_SHA1_PKCS_PSS = 7,
    KM_RSA_SHA224_PKCS_PSS = 8,
    KM_RSA_SHA256_PKCS_PSS = 9,
    KM_RSA_SHA384_PKCS_PSS = 10,
    KM_RSA_SHA512_PKCS_PSS = 11,
    KM_RSA_NODIGEST_NOPADDING = 12,
} rsa_algorithm_t;

/* keymaster cmd id */
enum SVC_KEYMASTER_CMD_ID {
    KM_CMD_ID_INVALID = 0x0,
    KM_CMD_ID_CONFIGURE,
    KM_CMD_ID_GENERATE_KEY,
    KM_CMD_ID_GET_KEY_CHARACTER,
    KM_CMD_ID_IMPORT_KEY,
    KM_CMD_ID_EXPORT_KEY,
    KM_CMD_ID_ATTEST_KEY,
    KM_CMD_ID_UPGRADE,
    KM_CMD_ID_BEGIN,
    KM_CMD_ID_UPDATE,
    KM_CMD_ID_FINISH,
    KM_CMD_ID_ABORT,
    KM_CMD_ID_STORE_KB,
    KM_CMD_ID_VERIFY_KB,
    KM_CMD_ID_STORE_IDENTIFIERS,
    KM_CMD_ID_VERIFY_IDENTIFIERS,
    KM_CMD_ID_DESTROY_IDENTIFIERS,
    KM_CMD_ID_VERIFY_ATTESTATIONIDS,
    KM_CMD_ID_KB_EIMA_POLICY_SET = 0x1E,
    KM_CMD_ID_DELETE_KEY = 0x1F,
    KM_CMD_ID_QUERY_ATTESTATION_CERTS = 0x22,
    KM_CMD_ID_DELETE_ALL_ATTESTATION_CERTS = 0x23,
    KM_CMD_ID_QUERY_IDENTIFIERS = 0x24,
    KM_CMD_ID_DELETE_ALL_IDENTIFIERS = 0x25,
    KM_CMD_ID_STORE_KB_SP = 0x26,
};

/* RSA private key metadata */
struct rsa_priv_header {
    uint32_t exp_len; /* *< Private key exponent length */
};

/* RSA CRT private key metadata */
struct rsa_crtpriv_header {
    uint32_t p_len;    /* *< Prime p length */
    uint32_t q_len;    /* *< Prime q length */
    uint32_t dp_len;   /* *< DP length */
    uint32_t dq_len;   /* *< DQ length */
    uint32_t qinv_len; /* *< QP length */
};

/* Key metadata (key size, modulus/exponent lengths, etc..) */
struct rsa_key_header {
    uint32_t key_type;    /* *< RSA key pair type. RSA or RSA CRT */
    uint32_t key_size_bytes;    /* *< RSA key size */
    uint32_t pub_mod_len; /* *< Public key modulus length */
    uint32_t pub_exp_len; /* *< Public key exponent length */
    union {
        struct rsa_priv_header rsa_priv;       /* *< RSA private key */
        struct rsa_crtpriv_header crtrsa_priv; /* *< RSA CRT private key */
    };
};

/* Key metadata of ecc */
struct ec_key_header {
    uint32_t key_size;
    uint8_t pc;
    uint32_t x_len;
    uint32_t y_len;
    uint32_t priv_key_len;
};

/* Pub key metadata for ec and rsa */
struct pub_key_header {
    keymaster_algorithm_t alg; /* key type ec or rsa */
    uint32_t key_size;         /* key size in bites */
    uint32_t n_or_x_len;       /* n len for rsa or x len for ec */
    uint32_t e_or_y_len;       /* e len for rsa or y len for ec */
};

typedef struct {
    uint8_t hmac[HMAC_SIZE];
    uint32_t used_count;
} key_record;

struct kb_crypto_factors {
    keymaster_blob_t app_id; /* application id or enhanced application id */
    keymaster_blob_t inse_factor; /* inse factor */
};

struct keyblob_crypto_ctx {
    uint32_t keyblob_version; /* keyblob version */
    uint32_t op_mode; /* crypto mode: enc/dec */
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    uint32_t iterate_flag; /* kdf iterate flag */
#endif
    keymaster_blob_t iv; /* aes iv */
    struct kb_crypto_factors factors; /* keyblob crypto factor */
};
#endif