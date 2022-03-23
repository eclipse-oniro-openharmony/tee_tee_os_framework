/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: cc manager implementation
 * Create: 2018-05-18
 */
#ifndef CCMGR_TEM_SASI_H
#define CCMGR_TEM_SASI_H

#define SASI_ECPKI_DOMAIN_NAME_MAX_LENGTH_IN_BYTES     20
#define SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS           18
#define SASI_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS (3 * SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS)
#define SASI_HASH_USER_CTX_SIZE_IN_WORDS               133
#define SASI_PKA_DOMAIN_LLF_BUFF_SIZE_IN_WORDS         (10 + 3 * SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS)

/* The valid key sizes in bits for RSA primitives (exponentiation) */
#define SASI_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS \
    ((SASI_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS + 64) / SASI_BITS_IN_32BIT_WORD)
#define SASI_ECPKI_MODUL_MAX_LENGTH_IN_BITS 521

/* ! size of buffers for Barrett modulus tag NP, used in PKI algorithms. */
#define SASI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS       5
#define SASI_PKA_ECPKI_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS SASI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS

#define SASI_PKA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS SASI_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS

#define SASI_PKA_PUB_KEY_BUFF_SIZE_IN_WORDS (2 * SASI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS)

#define SASI_PKA_PRIV_KEY_BUFF_SIZE_IN_WORDS (2 * SASI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS)

#define SASI_PKA_KGDATA_BUFF_SIZE_IN_WORDS (3 * SASI_PKA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS)

#define SASI_ECPKI_ORDER_MAX_LENGTH_IN_WORDS (SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1)

#define SASI_PKA_DOMAIN_BUFF_SIZE_IN_WORDS (2 * SASI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS)

#define SASI_PKA_EL_GAMAL_BUFF_MAX_LENGTH_IN_WORDS (4 * SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 4)

/* ECC NAF buffer definitions */
#define COUNT_NAF_WORDS_PER_KEY_WORD 8 /* !< \internal Change according to NAF representation (? 2) */
#define SASI_PKA_ECDSA_NAF_BUFF_MAX_LENGTH_IN_WORDS \
    (COUNT_NAF_WORDS_PER_KEY_WORD * SASI_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + 1)

#ifndef SSI_SUPPORT_ECC_SCA_SW_PROTECT
/* on fast SCA non protected mode required additional buffers for NAF key */
#define SASI_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS \
    (SASI_PKA_ECDSA_NAF_BUFF_MAX_LENGTH_IN_WORDS + SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 2)
#else
#define SASI_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS 1 /* (4*SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS) */
#endif

#define SASI_PKA_ECPKI_BUILD_TMP_BUFF_MAX_LENGTH_IN_WORDS \
    (3 * SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + SASI_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define SASI_PKA_ECDSA_SIGN_BUFF_MAX_LENGTH_IN_WORDS \
    (6 * SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + SASI_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define SASI_PKA_ECDH_BUFF_MAX_LENGTH_IN_WORDS \
    (2 * SASI_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + SASI_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define SASI_PKA_KG_BUFF_MAX_LENGTH_IN_WORDS \
    (2 * SASI_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + SASI_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define SASI_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS (3 * SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS)

#define SASI_OK (0)

#ifndef align_up_size
#define align_up_size(x, alignment) ((sizeof(x) + ((alignment) - 1)) / alignment)
#endif

enum sasi_ecpki_hash_opmode {
    SASI_ECPKI_HASH_SHA1_MODE         = 0, /* !< HASH SHA1 mode. */
    SASI_ECPKI_HASH_SHA224_MODE       = 1, /* !< HASH SHA224 mode. */
    SASI_ECPKI_HASH_SHA256_MODE       = 2, /* !< HASH SHA256 mode. */
    SASI_ECPKI_HASH_SHA384_MODE       = 3, /* !< HASH SHA384 mode. */
    SASI_ECPKI_HASH_SHA512_MODE       = 4, /* !< HASH SHA512 mode. */
    SASI_ECPKI_AFTER_HASH_SHA1_MODE   = 5, /* !< After HASH SHA1 mode (message was already hashed). */
    SASI_ECPKI_AFTER_HASH_SHA224_MODE = 6, /* !< After HASH SHA224 mode (message was already hashed). */
    SASI_ECPKI_AFTER_HASH_SHA256_MODE = 7, /* !< After HASH SHA256 mode (message was already hashed). */
    SASI_ECPKI_AFTER_HASH_SHA384_MODE = 8, /* !< After HASH SHA384 mode (message was already hashed). */
    SASI_ECPKI_AFTER_HASH_SHA512_MODE = 9, /* !< After HASH SHA512 mode (message was already hashed). */
    SASI_ECPKI_HASH_NUM_OF_MODES,
    SASI_ECPKI_HASH_OP_MODE_LAST        = 0x7FFFFFFF,
};

struct sasi_hash_user_context {
    uint32_t buff[SASI_HASH_USER_CTX_SIZE_IN_WORDS];
};

enum sasi_ecpki_domainid {
    /* For prime field */
    SASI_ECPKI_DOMAINID_SECP160K1, /* !< EC secp160r1 */
    SASI_ECPKI_DOMAINID_SECP160R1, /* !< EC secp160k1 */
    SASI_ECPKI_DOMAINID_SECP160R2, /* !< EC secp160r2 */
    SASI_ECPKI_DOMAINID_SECP192K1, /* !< EC secp192k1 */
    SASI_ECPKI_DOMAINID_SECP192R1, /* !< EC secp192r1 */
    SASI_ECPKI_DOMAINID_SECP224K1, /* !< EC secp224k1 */
    SASI_ECPKI_DOMAINID_SECP224R1, /* !< EC secp224r1 */
    SASI_ECPKI_DOMAINID_SECP256K1, /* !< EC secp256k1 */
    SASI_ECPKI_DOMAINID_SECP256R1, /* !< EC secp256r1 */
    SASI_ECPKI_DOMAINID_SECP384R1, /* !< EC secp384r1 */
    SASI_ECPKI_DOMAINID_SECP521R1, /* !< EC secp521r1 */

    SASI_ECPKI_DOMAINID_BUILDED,   /* !< User given, not identified. */
    SASI_ECPKI_DOMAINID_OFFMODE,

    SASI_ECPKI_DOMAINID_LAST = 0x7FFFFFFF,
};

struct sasi_ecpki_domain {
    /* ! EC modulus: P. */
    uint32_t ec_p[SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    /* ! EC equation parameters a, b. */
    uint32_t ec_a[SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t ec_b[SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    /* ! Order of generator. */
    uint32_t ec_r[SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
    /* ! EC cofactor EC_Cofactor_K
      Generator (EC base point) coordinates in projective form. */
    uint32_t ec_gx[SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t ec_gy[SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t ec_h;
    /* ! include the specific fields that are used by the low level. */
    uint32_t llf_buff[SASI_PKA_DOMAIN_LLF_BUFF_SIZE_IN_WORDS];
    /* ! Size of fields in bits. */
    uint32_t mod_size_in_bits;
    uint32_t ord_size_in_bits;
    /* ! Size of each inserted Barret tag in words; 0 - if not inserted. */
    uint32_t barr_tagsize_in_words;
    /* ! EC Domain identifier. */
    enum sasi_ecpki_domainid domain_id;
    int8_t name[SASI_ECPKI_DOMAIN_NAME_MAX_LENGTH_IN_BYTES];
};

struct sasi_ecpki_publkey {
    /* ! Public Key coordinates. */
    uint32_t x[SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t y[SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    struct sasi_ecpki_domain domain;
    uint32_t point_type;
};

#define SASI_HASH_RESULT_SIZE_IN_WORDS 16

struct sasi_ecpki_user_publkey {
    uint32_t valid_tag;
    uint32_t publkey_db_buff[align_up_size(struct sasi_ecpki_publkey, 4)];
};

struct sasi_verify_context {
    /* A user's buffer for the Private Key Object - */
    struct sasi_ecpki_user_publkey ecdsa_signer_publkey;
    /* HASH specific data and buffers */
    uint32_t hash_user_ctx_buff[sizeof(struct sasi_hash_user_context)];
    uint32_t hash_result[SASI_HASH_RESULT_SIZE_IN_WORDS];
    uint32_t hash_result_size_words;
    enum sasi_ecpki_hash_opmode hash_mode;
    uint32_t sasi_ecdsa_verint_buff[SASI_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS];
};

struct sasi_ecdsa_verify_user_context {
    uint32_t context_buff[align_up_size(struct sasi_verify_context, 4)];
    uint32_t valid_tag;
};

enum sasi_ecpki_sca_protection {
    SCAP_INACTIVE,
    SCAP_ACTIVE,
    SCAP_OFF_MODE,
    SCAP_LAST = 0x7FFFFFFF
};

struct sasi_ecpki_privkey {
    /* ! Private Key data. */
    uint32_t privkey[SASI_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
    struct sasi_ecpki_domain domain;
    enum sasi_ecpki_sca_protection sca_protection;
};

struct sasi_ecpki_user_privkey {
    uint32_t valid_tag;
    uint32_t privkey_db_buff[align_up_size(struct sasi_ecpki_privkey, 4)];
};

struct sign_ecdsa_sign_context {
    /* A user's buffer for the Private Key Object - */
    struct sasi_ecpki_user_privkey ecdsa_signer_privkey;
    /* HASH specific data and buffers */
    uint32_t hash_user_ctx_buff[sizeof(struct sasi_ecpki_user_privkey)];
    uint32_t hash_result[SASI_HASH_RESULT_SIZE_IN_WORDS];
    uint32_t hash_result_size_words;
    enum sasi_ecpki_hash_opmode hash_mode;
    uint32_t sasi_ecdsa_sign_intbuff[SASI_PKA_ECDSA_SIGN_BUFF_MAX_LENGTH_IN_WORDS];
};

struct sasi_ecdsa_sign_user_context {
    uint32_t context_buff[align_up_size(struct sign_ecdsa_sign_context, 4)];
    uint32_t valid_tag;
};

#endif /* CCMGR_TEM_SASI_H */
