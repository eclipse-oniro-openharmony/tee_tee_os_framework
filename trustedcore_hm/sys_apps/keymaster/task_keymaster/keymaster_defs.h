/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2020. All rights reserved.
 * Description: keymaster definitions
 * Create: 2015-01-17
 */

#ifndef __KM_DEF_H
#define __KM_DEF_H

#include "string.h"
#include "tee_internal_api.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#define EXTRA_ITERATE 1
#define NO_EXTRA_ITERATE 0
#endif
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* total list types defined in keymaster_def.h */
#define ALGORITHM_MAX 4
#define BLOCK_MAX     4
#define PADDING_MAX   6
#define DIGEST_MAX    7
#define FORMAT_MAX    3
#define KM_KEY_GENERATED         0
#define KM_KEY_IMPORTED          1
#define KM_KEY_SECURELY_IMPORTED 2

#define KM_FACTOR_1 1
#define KM_FACTOR_2 2
#define KM_FACTOR_3 3
#define KM_FACTOR_7 7

#define KM_NUM_BYTES_1  1
#define KM_NUM_BYTES_2  2
#define KM_NUM_BYTES_3  3
#define KM_NUM_BYTES_4  4
#define KM_WORD_BYTES   2
#define KM_UINT32_BYTES 4

#define KM_SHIFT_BITS_32 32
#define IV_LEN           16
#define KM_MAC_MIN_TAG 64
#define KM_AES_MIN_TAG 96
#define KM_AES_MAX_TAG 128

#define AES_KEY_LEN     32

#define KM_BYTE_SIZE_8   8
#define KM_KEY_SIZE_128  128
#define KM_KEY_SIZE_192  192
#define KM_KEY_SIZE_256  256
#define KM_KEY_SIZE_1536 (192 * 8)
#define KM_KEY_SIZE_4096 4096

#define KM_ECC_SECP256_R1 256
#define KM_ECC_SECP160_R1 160
#define KM_ECC_SECP192_R1 192
#define KM_ECC_SECP224_R1 224
#define KM_ECC_SECP384_R1 384
#define KM_ECC_SECP521_R1 521
#define KM_MS_PER_SEC 1000

#define KM_INPUT_BLOB_MAX_LEN (4 * 1024)

typedef enum {
    AUTH_TOKEN_MAC_LENGTH = 32,
} keymaster_mac_length_t;

/*
 * Authorization tags each have an associated type.  This enumeration facilitates tagging each with
 * a type, by using the high four bits (of an implied 32-bit unsigned enum value) to specify up to
 * 16 data types.  These values are ORed with tag IDs to generate the final tag ID values.
 */
typedef enum {
    KM_INVALID   = 0 << 28, /* Invalid type, used to designate a tag as uninitialized */
    KM_ENUM      = 1 << 28,
    KM_ENUM_REP  = 2 << 28, /* Repeatable enumeration value. */
    KM_UINT      = 3 << 28,
    KM_UINT_REP  = 4 << 28, /* Repeatable integer value */
    KM_ULONG     = 5 << 28,
    KM_DATE      = 6 << 28,
    KM_BOOL      = 7 << 28,
    KM_BIGNUM    = 8 << 28,
    KM_BYTES     = 9 << 28,
    KM_ULONG_REP = 10 << 28, /* Repeatable long value */
} keymaster_tag_type_t;

typedef enum {
    KM_TAG_INVALID = KM_INVALID | 0,

    /* Tags that must be semantically enforced by hardware and software implementations. */
    /* Crypto parameters */
    KM_TAG_PURPOSE        = KM_ENUM_REP | 1, /* keymaster_purpose_t. */
    KM_TAG_ALGORITHM      = KM_ENUM | 2,     /* keymaster_algorithm_t. */
    KM_TAG_KEY_SIZE       = KM_UINT | 3,     /* Key size in bits. */
    KM_TAG_BLOCK_MODE     = KM_ENUM_REP | 4, /* keymaster_block_mode_t. */
    KM_TAG_DIGEST         = KM_ENUM_REP | 5, /* keymaster_digest_t. */
    KM_TAG_PADDING        = KM_ENUM_REP | 6, /* keymaster_padding_t. */
    KM_TAG_CALLER_NONCE   = KM_BOOL | 7,     /* Allow caller to specify nonce or IV. */
    KM_TAG_MIN_MAC_LENGTH = KM_UINT | 8,     /* Minimum length of MAC or AEAD authentication tag in bits. */
    KM_TAG_KDF            = KM_ENUM_REP | 9, /* keymaster_kdf_t (keymaster2) */
    KM_TAG_EC_CURVE       = KM_ENUM | 10,    /* keymaster_ec_curve_t (keymaster2) */

    /* Algorithm-specific. */
    KM_TAG_RSA_PUBLIC_EXPONENT    = KM_ULONG | 200,
    KM_TAG_ECIES_SINGLE_HASH_MODE = KM_BOOL | 201, /* Whether the ephemeral public key is fed into the KDF */
    /*
     * If true, attestation certificates for this key will contain an application-scoped and
     * time-bounded device-unique ID. (keymaster2)
     */
    KM_TAG_INCLUDE_UNIQUE_ID = KM_BOOL | 202,

    /* Other hardware-enforced. */
    KM_TAG_BLOB_USAGE_REQUIREMENTS = KM_ENUM | 301, /* keymaster_key_blob_usage_requirements_t */
    KM_TAG_BOOTLOADER_ONLY         = KM_BOOL | 302, /* Usable only by bootloader */
    /*
     * Whether key is rollback-resistant.  Specified in the key description provided to generateKey
     * or importKey if rollback resistance is desired. If the implementation cannot provide rollback
     * resistance, it must return ROLLBACK_RESISTANCE_UNAVAILABLE.
     */
    KM_TAG_ROLLBACK_RESISTANCE = KM_BOOL | 303,
    /*
     * HARDWARE_TYPE specifies the type of the secure hardware that is requested for the key
     * generation / import.  See the SecurityLevel enum.  In the absence of this tag, keystore must
     * use TRUSTED_ENVIRONMENT.  If this tag is present and the requested hardware type is not
     * available, Keymaster returns HARDWARE_TYPE_UNAVAILABLE. This tag is not included in
     * attestations, but hardware type must be reflected in the Keymaster SecurityLevel of the
     * attestation header.
     */
    KM_TAG_HARDWARE_TYPE = KM_ENUM | 304,

    /*
     * Tags that should be semantically enforced by hardware if possible and will otherwise be enforced
     * by software (keystore).
     */
    /* Key validity period */
    KM_TAG_ACTIVE_DATETIME             = KM_DATE | 400, /* Start of validity */
    KM_TAG_ORIGINATION_EXPIRE_DATETIME = KM_DATE | 401, /* Date when new "messages" should no longer be created. */
    /* Date when existing "messages" should no longer be trusted. */
    KM_TAG_USAGE_EXPIRE_DATETIME = KM_DATE | 402,
    /* Minimum elapsed time between cryptographic operations with the key. */
    KM_TAG_MIN_SECONDS_BETWEEN_OPS = KM_UINT | 403,
    KM_TAG_MAX_USES_PER_BOOT       = KM_UINT | 404, /* Number of times the key can be used per boot. */

    /* User authentication */
    KM_TAG_ALL_USERS = KM_BOOL | 500, /* Reserved for future use -- ignore */
    KM_TAG_USER_ID   = KM_UINT | 501, /* Reserved for future use -- ignore */
    /*
     * Secure ID of authorized user or authenticator(s). Disallowed if KM_TAG_ALL_USERS or
     * KM_TAG_NO_AUTH_REQUIRED is present.
     */
    KM_TAG_USER_SECURE_ID   = KM_ULONG_REP | 502,
    KM_TAG_NO_AUTH_REQUIRED = KM_BOOL | 503, /* If key is usable without authentication. */
    /*
     * Bitmask of authenticator types allowed when KM_TAG_USER_SECURE_ID contains a secure user ID, rather than a
     * secure authenticator ID.  Defined in hw_authenticator_type_t in hw_auth_token.h.
     */
    KM_TAG_USER_AUTH_TYPE = KM_ENUM | 504,
    /*
     * Required freshness of user authentication for private/secret key operations, in seconds. Public key operations
     * require no authentication. If absent, authentication is required for every use.
     * Authentication state is lost when the device is powered off.
     */
    KM_TAG_AUTH_TIMEOUT = KM_UINT | 505,
    /* Allow key to be used after authentication timeout if device is still on-body (requires secure on-body sensor. */
    KM_TAG_ALLOW_WHILE_ON_BODY = KM_BOOL | 506,
    /*
     * TRUSTED_USER_PRESENCE_REQUIRED is an optional feature that specifies that this key must be
     * unusable except when the user has provided proof of physical presence.  Proof of physical
     * presence must be a signal that cannot be triggered by an attacker who doesn't have one of:
     *
     *    a) Physical control of the device or
     *
     *    b) Control of the secure environment that holds the key.
     *
     * For instance, proof of user identity may be considered proof of presence if it meets the
     * requirements.  However, proof of identity established in one security domain (e.g. TEE) does
     * not constitute proof of presence in another security domain (e.g. StrongBox), and no
     * mechanism analogous to the authentication token is defined for communicating proof of
     * presence across security domains.
     *
     * Some examples:
     *
     *     A hardware button hardwired to a pin on a StrongBox device in such a way that nothing
     *     other than a button press can trigger the signal constitutes proof of physical presence
     *     for StrongBox keys.
     *
     *     Fingerprint authentication provides proof of presence (and identity) for TEE keys if the
     *     TEE has exclusive control of the fingerprint scanner and performs fingerprint matching.
     *
     *     Password authentication does not provide proof of presence to either TEE or StrongBox,
     *     even if TEE or StrongBox does the password matching, because password input is handled by
     *     the non-secure world, which means an attacker who has compromised Android can spoof
     *     password authentication.
     *
     * Note that no mechanism is defined for delivering proof of presence to Keymaster,
     * except perhaps as implied by an auth token.  This means that Keymaster must be able to check
     * proof of presence some other way.  Further, the proof of presence must be performed between
     * begin() and the first call to update() or finish().  If the first update() or the finish()
     * call is made without proof of presence, the keymaster method must return
     * ErrorCode::PROOF_OF_PRESENCE_REQUIRED and abort the operation.  The caller must delay the
     * update() or finish() call until proof of presence has been provided, which means the caller
     * must also have some mechanism for verifying that the proof has been provided.
     *
     * Only one operation requiring TUP may be in flight at a time.  If begin() has already been
     * called on one key with TRUSTED_USER_PRESENCE_REQUIRED, and another begin() comes in for that
     * key or another with TRUSTED_USER_PRESENCE_REQUIRED, Keymaster must return
     * ErrorCode::CONCURRENT_PROOF_OF_PRESENCE_REQUESTED.
     */
    KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = KM_BOOL | 507,

    /*
     * TRUSTED_CONFIRMATION_REQUIRED is only applicable to keys with KeyPurpose SIGN, and specifies
     *  that this key must not be usable unless the user provides confirmation of the data to be
     *  signed. Confirmation is proven to keymaster via an approval token. See CONFIRMATION_TOKEN,
     *  as well as the ConfirmatinUI HAL.
     *
     * If an attempt to use a key with this tag does not have a cryptographically valid
     * CONFIRMATION_TOKEN provided to finish() or if the data provided to update()/finish() does not
     * match the data described in the token, keymaster must return NO_USER_CONFIRMATION.
     */
    KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = KM_BOOL | 508,
    /* Require the device screen to be unlocked if the key is used. */
    KM_TAG_UNLOCKED_DEVICE_REQUIRED = KM_BOOL | 509,

    /* Application access control */
    /* Specified to indicate key is usable by all applications. */
    KM_TAG_ALL_APPLICATIONS = KM_BOOL | 600,
    /* Byte string identifying the authorized application. */
    KM_TAG_APPLICATION_ID = KM_BYTES | 601,
    /*
     * If true, private/secret key can be exported, but only if all access control requirements for use
     * are met. (keymaster2)
     */
    KM_TAG_EXPORTABLE = KM_BOOL | 602,

    /*
     * Semantically unenforceable tags, either because they have no specific meaning or because
     * they're informational only.
     */
    KM_TAG_APPLICATION_DATA  = KM_BYTES | 700, /* Data provided by authorized application. */
    KM_TAG_CREATION_DATETIME = KM_DATE | 701,  /* Key creation time */
    KM_TAG_ORIGIN            = KM_ENUM | 702,  /* keymaster_key_origin_t. */
    /* google add a new tag KM_TAG_ROLLBACK_RESISTANCE to replace this tag on P */
    KM_TAG_ROLLBACK_RESISTANT    = KM_BOOL | 703,  /* Whether key is rollback-resistant. */
    KM_TAG_ROOT_OF_TRUST         = KM_BYTES | 704, /* Root of trust ID. */
    KM_TAG_OS_VERSION            = KM_UINT | 705,  /* Version of system (keymaster2) */
    KM_TAG_OS_PATCHLEVEL         = KM_UINT | 706,  /* Patch level of system (keymaster2) */
    KM_TAG_UNIQUE_ID             = KM_BYTES | 707, /* Used to provide unique ID in attestation */
    KM_TAG_ATTESTATION_CHALLENGE = KM_BYTES | 708, /* Used to provide challenge in attestation */
    /* Used to identify the set of possible applications of which one has initiated a key attestation */
    KM_TAG_ATTESTATION_APPLICATION_ID = KM_BYTES | 709,
    /* Used to provide the device's brand name to be included in attestation */
    KM_TAG_ATTESTATION_ID_BRAND       = KM_BYTES | 710,
    /* Used to provide the device's device name to be included in attestation */
    KM_TAG_ATTESTATION_ID_DEVICE = KM_BYTES | 711,
    /* Used to provide the device's product name to be included in attestation */
    KM_TAG_ATTESTATION_ID_PRODUCT = KM_BYTES | 712,
    /* Used to provide the device's serial number to be included in attestation */
    KM_TAG_ATTESTATION_ID_SERIAL = KM_BYTES | 713,
    KM_TAG_ATTESTATION_ID_IMEI   = KM_BYTES | 714, /* Used to provide the device's IMEI to be included in attestation */
    KM_TAG_ATTESTATION_ID_MEID   = KM_BYTES | 715, /* Used to provide the device's MEID to be included in attestation */
    /* Used to provide the device's manufacturer name to be included in attestation */
    KM_TAG_ATTESTATION_ID_MANUFACTURER = KM_BYTES | 716,
    /* Used to provide the device's model name to be included in attestation */
    KM_TAG_ATTESTATION_ID_MODEL = KM_BYTES | 717,

    /*
     * Patch level of vendor image.  The value is an integer of the form YYYYMM, where YYYY is the
     * four-digit year when the vendor image was released and MM is the two-digit month.  During
     * each boot, the bootloader must provide the patch level of the vendor image to keymaser
     * (mechanism is implemntation-defined).  When keymaster keys are created or updated, the
     * VENDOR_PATCHLEVEL tag must be cryptographically bound to the keys, with the current value as
     * provided by the bootloader.  When keys are used, keymaster must verify that the
     * VENDOR_PATCHLEVEL bound to the key matches the current value.  If they do not match,
     * keymaster must return ErrorCode::KEY_REQUIRES_UPGRADE.  The client must then call upgradeKey.
     */
    KM_TAG_VENDOR_PATCHLEVEL = KM_UINT | 718,

    /*
     * Patch level of boot image.  The value is an integer of the form YYYYMM, where YYYY is the
     * four-digit year when the boot image was released and MM is the two-digit month.  During each
     * boot, the bootloader must provide the patch level of the boot image to keymaser (mechanism is
     * implemntation-defined).  When keymaster keys are created or updated, the BOOT_PATCHLEVEL tag
     * must be cryptographically bound to the keys, with the current value as provided by the
     * bootloader.  When keys are used, keymaster must verify that the BOOT_PATCHLEVEL bound to the
     * key matches the current value.  If they do not match, keymaster must return
     * ErrorCode::KEY_REQUIRES_UPGRADE.  The client must then call upgradeKey.
     */
    KM_TAT_BOOT_PATCHLEVEL = KM_UINT | 719,

    /* Tags used only to provide data to or receive data from operations */
    KM_TAG_ASSOCIATED_DATA = KM_BYTES | 1000, /* Used to provide associated data for AEAD modes. */
    KM_TAG_NONCE           = KM_BYTES | 1001, /* Nonce or Initialization Vector */
    /*
     * Authentication token that proves secure user authentication has been performed.
     * Structure defined in hw_auth_token_t in hw_auth_token.h.
     */
    KM_TAG_AUTH_TOKEN = KM_BYTES | 1002,
    KM_TAG_MAC_LENGTH = KM_UINT | 1003, /* MAC or AEAD authentication tag length in bits. */
    /* Whether the device has beeen factory reset since the last unique ID rotation.  Used for key attestation. */
    KM_TAG_RESET_SINCE_ID_ROTATION = KM_BOOL | 1004,
    /*
     * CONFIRMATION_TOKEN is used to deliver a cryptographic token proving that the user confirmed a
     * signing request. The content is a full-length HMAC-SHA256 value. See the ConfirmationUI HAL
     * for details of token computation.
     */
    KM_TAG_CONFIRMATION_TOKEN = KM_BYTES | 1005,

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    /*
     * Customization Definitions, the tags below are used for enhanced keyblob using enhanced appid
     * as kdf factor
     */
    KM_TAG_HW_ENHANCED_KEY = KM_BOOL | 90000, /* Specify the keyblob is a enhanced key */
    KM_TAG_HW_ENHANCED_KEY_APPID = KM_BYTES | 90001, /* Specify the keyblob's enhanced appid */
#endif
} keymaster_tag_t;

/*
 * Algorithms that may be provided by keymaster implementations.  Those that must be provided by all
 * implementations are tagged as "required".
 */
typedef enum {
    /* Asymmetric algorithms. */
    KM_ALGORITHM_RSA = 1,
    /* KM_ALGORITHM_DSA = 2, -- Removed, do not re-use value 2. */
    KM_ALGORITHM_EC = 3,

    /* Block ciphers algorithms */
    KM_ALGORITHM_AES        = 32,
    KM_ALGORITHM_TRIPLE_DES = 33,

    /* MAC algorithms */
    KM_ALGORITHM_HMAC = 128,
} keymaster_algorithm_t;

/* Symmetric block cipher modes provided by keymaster implementations. */
typedef enum {
    /*
     * Unauthenticated modes, usable only for encryption/decryption and not generally recommended
     * except for compatibility with existing other protocols.
     */
    KM_MODE_ECB = 1,
    KM_MODE_CBC = 2,
    KM_MODE_CTR = 3,

    /*
     * Authenticated modes, usable for encryption/decryption and signing/verification.  Recommended
     * over unauthenticated modes for all purposes.
     */
    KM_MODE_GCM = 32,
} keymaster_block_mode_t;

/*
 * Padding modes that may be applied to plaintext for encryption operations.  This list includes
 * padding modes for both symmetric and asymmetric algorithms.  Note that implementations should not
 * provide all possible combinations of algorithm and padding, only the
 * cryptographically-appropriate pairs.
 */
typedef enum {
    KM_PAD_NONE                  = 1, /* deprecated */
    KM_PAD_RSA_OAEP              = 2,
    KM_PAD_RSA_PSS               = 3,
    KM_PAD_RSA_PKCS1_1_5_ENCRYPT = 4,
    KM_PAD_RSA_PKCS1_1_5_SIGN    = 5,
    KM_PAD_PKCS7                 = 64,
} keymaster_padding_t;

/* Digests provided by keymaster implementations. */
typedef enum {
    KM_DIGEST_NONE = 0,
    /* Optional, may not be implemented in hardware, will be handled in software if needed. */
    KM_DIGEST_MD5 = 1,
    KM_DIGEST_SHA1 = 2,
    KM_DIGEST_SHA_2_224 = 3,
    KM_DIGEST_SHA_2_256 = 4,
    KM_DIGEST_SHA_2_384 = 5,
    KM_DIGEST_SHA_2_512 = 6,
} keymaster_digest_t;

/* Key derivation functions, mostly used in ECIES. */
typedef enum {
    /* Do not apply a key derivation function; use the raw agreed key */
    KM_KDF_NONE = 0,
    /* HKDF defined in RFC 5869 with SHA256 */
    KM_KDF_RFC5869_SHA256 = 1,
    /* KDF1 defined in ISO 18033-2 with SHA1 */
    KM_KDF_ISO18033_2_KDF1_SHA1 = 2,
    /* KDF1 defined in ISO 18033-2 with SHA256 */
    KM_KDF_ISO18033_2_KDF1_SHA256 = 3,
    /* KDF2 defined in ISO 18033-2 with SHA1 */
    KM_KDF_ISO18033_2_KDF2_SHA1 = 4,
    /* KDF2 defined in ISO 18033-2 with SHA256 */
    KM_KDF_ISO18033_2_KDF2_SHA256 = 5,
} keymaster_kdf_t;

/* Supported EC curves, used in ECDSA/ECIES. */
typedef enum {
    KM_EC_CURVE_P_224 = 0,
    KM_EC_CURVE_P_256 = 1,
    KM_EC_CURVE_P_384 = 2,
    KM_EC_CURVE_P_521 = 3,
    KM_EC_CURVE_P_OFF,
} keymaster_ec_curve_t;

/*
 * The origin of a key (or pair), i.e. where it was generated.  Note that KM_TAG_ORIGIN can be found
 * in either the hardware-enforced or software-enforced list for a key, indicating whether the key
 * is hardware or software-based.  Specifically, a key with KM_ORIGIN_GENERATED in the
 * hardware-enforced list is guaranteed never to have existed outide the secure hardware.
 */
typedef enum {
    KM_ORIGIN_GENERATED = 0, /* Generated in keymaster.  Should not exist outside the TEE. */
    KM_ORIGIN_DERIVED   = 1, /* Derived inside keymaster.  Likely exists off-device. */
    KM_ORIGIN_IMPORTED  = 2, /* Imported into keymaster.  Existed as cleartext in Android. */
    /*
     * Keymaster did not record origin.  This value can only be seen on
     * keys in a keymaster0 implementation.  The keymaster0 adapter uses
     * this value to document the fact that it is unkown whether the key
     * was generated inside or imported into keymaster.
     */
    KM_ORIGIN_UNKNOWN = 3,
    /*
     * Securely imported into Keymaster.  Was created elsewhere, and passed securely through Android
     * to secure hardware.
     */
    KM_ORIGIN_SECURELY_IMPORTED = 4,
} keymaster_key_origin_t;

/*
 * Usability requirements of key blobs.  This defines what system functionality must be available
 * for the key to function.  For example, key "blobs" which are actually handles referencing
 * encrypted key material stored in the file system cannot be used until the file system is
 * available, and should have BLOB_REQUIRES_FILE_SYSTEM.  Other requirements entries will be added
 * as needed for implementations.  This type is new in 0_4.
 */
typedef enum {
    KM_BLOB_STANDALONE           = 0,
    KM_BLOB_REQUIRES_FILE_SYSTEM = 1,
} keymaster_key_blob_usage_requirements_t;

/* Possible purposes of a key (or pair). This type is new in 0_4. */
typedef enum {
    KM_PURPOSE_ENCRYPT            = 0,      /* Usable with RSA, EC and AES keys. */
    KM_PURPOSE_DECRYPT            = 1,      /* Usable with RSA, EC and AES keys. */
    KM_PURPOSE_SIGN               = 2,      /* Usable with RSA, EC and HMAC keys. */
    KM_PURPOSE_VERIFY             = 3,      /* Usable with RSA, EC and HMAC keys. */
    KM_PURPOSE_DERIVE_KEY         = 4,      /* Usable with EC keys. */
    KM_PURPOSE_WRAP_KEY           = 5,      /* Usable with wrapping keys. */
    KM_PURPOSE_ROLLBACK_RESISTANT = 0xBACF, /* Whether the key need rollback-resistant support. */
} keymaster_purpose_t;

typedef struct {
    uint8_t *data_addr;
    uint32_t data_length;
} keymaster_blob_t;

typedef struct {
    uint32_t data_offset;
    uint32_t data_length;
} keymaster_offset_t;

typedef struct {
    keymaster_tag_t tag;
    union {
        uint32_t enumerated;   /* KM_ENUM and KM_ENUM_REP */
        bool boolean;          /* KM_BOOL */
        uint32_t integer;      /* KM_INT and KM_INT_REP */
        uint64_t long_integer; /* KM_LONG */
        uint64_t date_time;    /* KM_DATE */
        keymaster_offset_t blob; /* KM_BIGNUM and KM_BYTES */
    };
} keymaster_key_param_t;

typedef struct __attribute__((__packed__)) {
    uint32_t length;
    keymaster_key_param_t *params; /* may be NULL if length == 0 */
} keymaster_key_param_set_t;

/*
 * Parameters that define a key's characteristics, including authorized modes of usage and access
 * control restrictions.  The parameters are divided into two categories, those that are enforced by
 * secure hardware, and those that are not.  For a software-only keymaster implementation the
 * enforced array must NULL.  Hardware implementations must enforce everything in the enforced
 * array.
 */
typedef struct {
    keymaster_key_param_set_t hw_enforced;
    keymaster_key_param_set_t sw_enforced;
} keymaster_key_characteristics_t;

typedef struct __attribute__((__packed__)) {
    keymaster_blob_t *entries;
    uint32_t entry_count;
} keymaster_cert_chain_t;

typedef enum {
    /*
     * Full chain of trust extending from the bootloader to verified partitions, including the bootloader, boot
     * partition, and all verified partitions
     */
    KM_VERIFIED_BOOT_VERIFIED = 0,
    /*
     * The boot partition has been verified using the embedded certificate, and the signature is valid. The bootloader
     * displays a warning and the fingerprint of the public key before allowing the boot process to continue.
     */
    KM_VERIFIED_BOOT_SELF_SIGNED = 1,
    /*
     * The device may be freely modified. Device integrity is left to the user to verify out-of-band. The bootloader
     * displays a warning to the user before allowing the boot process to continue
     */
    KM_VERIFIED_BOOT_UNVERIFIED = 2,
    /*
     * The device failed verification. The bootloader displays a warning and stops the boot process, so no keymaster
     * implementation should ever actually return this value, since it should not run.  Included here only for
     * completeness.
     */
    KM_VERIFIED_BOOT_FAILED = 3,
} keymaster_verified_boot_t;

/*
 * Hardware authentication type, used by HardwareAuthTokens to specify the mechanism used to
 * authentiate the user, and in KeyCharacteristics to specify the allowable mechanisms for
 * authenticating to activate a key.
 */
typedef enum HardwareAuthenticatorType {
    KM_HA_TYPE_NONE        = 0,
    KM_HA_TYPE_PASSWORD    = 1 << 0,
    KM_HA_TYPE_FINGERPRINT = 1 << 1,
    /* Additional entries must be powers of 2 */
    KM_HA_TYPE_ANY = 0xFFFFFFFF,
} keymaster_hardware_authenticator_type_t;

/* Device security levels. */
typedef enum {
    KM_SECURITY_LEVEL_SOFTWARE            = 0,
    KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1,
    /*
     * STRONGBOX specifies that the secure hardware satisfies the following requirements:
     *
     *    a) Has a discrete CPU.  The StrongBox device must not be the same CPU that is used to run
     *       the Android non-secure world, or any other untrusted code.  The StrongBox CPU must not
     *       share cache, RAM or any other critical resources with any device that runs untrusted
     *       code.
     *
     *    b) Has integral secure storage.  The StrongBox device must have its own non-volatile
     *       storage that is not accessible by any other hardware component.
     *
     *    c) Has a high-quality True Random Number Generator.  The StrongBox device must have sole
     *       control of and access to a high-quality TRNG which it uses for generating necessary
     *       random bits.  It must combine the output of this TRNG with caller-provided entropy in a
     *       strong CPRNG, as do non-Strongbox Keymaster implementations.
     *
     *    d) Is enclosed in tamper-resistant packaging.  The StrongBox device must have
     *       tamper-resistant packaging which provides obstacles to physical penetration which are
     *       higher than those provided by normal integrated circuit packages.
     *
     *    e) Provides side-channel resistance.  The StrongBox device must implement resistance
     *       against common side-channel attacks, including power analysis, timing analysis, EM
     *       snooping, etc.
     *
     * Devices with StrongBox Keymasters must also have a non-StrongBox Keymaster, which lives in
     * the higher-performance TEE.  Keystore must load both StrongBox (if available) and
     * non-StrongBox HALs and route key generation/import requests appropriately.  Callers that want
     * StrongBox keys must add Tag::HARDWARE_TYPE with value SecurityLevel::STRONGBOX to the key
     * description provided to generateKey or importKey.  Keytore must route the request to a
     * StrongBox HAL (a HAL whose isStrongBox method returns true).  Keymaster implementations that
     * receive a request for a Tag::HARDWARE_TYPE that is inappropriate must fail with
     * ErrorCode::HARDWARE_TYPE_UNAVAILABLE.
     */
    KM_SECURITY_LEVEL_STRONGBOX = 2, /* See IKeymaster::isStrongBox */
} keymaster_security_level_t;

/*
 * Formats for key import and export.  At present, only asymmetric key import/export is supported.
 * In the future this list will expand greatly to accommodate asymmetric key import/export.
 */
typedef enum {
    KM_KEY_FORMAT_X509  = 0, /* for public key export */
    KM_KEY_FORMAT_PKCS8 = 1, /* for asymmetric key pair import */
    KM_KEY_FORMAT_RAW   = 3, /* for symmetric key import */
} keymaster_key_format_t;

/*
 * The keymaster operation API consists of begin, update, finish and abort. This is the type of the
 * handle used to tie the sequence of calls together.  A 64-bit value is used because it's important
 * that handles not be predictable.  Implementations must use strong random numbers for handle
 * values.
 */
typedef enum {
    KM_ERROR_OK                                     = 0,
    KM_ERROR_ROOT_OF_TRUST_ALREADY_SET              = -1,
    KM_ERROR_UNSUPPORTED_PURPOSE                    = -2,
    KM_ERROR_INCOMPATIBLE_PURPOSE                   = -3,
    KM_ERROR_UNSUPPORTED_ALGORITHM                  = -4,
    KM_ERROR_INCOMPATIBLE_ALGORITHM                 = -5,
    KM_ERROR_UNSUPPORTED_KEY_SIZE                   = -6,
    KM_ERROR_UNSUPPORTED_BLOCK_MODE                 = -7,
    KM_ERROR_INCOMPATIBLE_BLOCK_MODE                = -8,
    KM_ERROR_UNSUPPORTED_MAC_LENGTH                 = -9,
    KM_ERROR_UNSUPPORTED_PADDING_MODE               = -10,
    KM_ERROR_INCOMPATIBLE_PADDING_MODE              = -11,
    KM_ERROR_UNSUPPORTED_DIGEST                     = -12,
    KM_ERROR_INCOMPATIBLE_DIGEST                    = -13,
    KM_ERROR_INVALID_EXPIRATION_TIME                = -14,
    KM_ERROR_INVALID_USER_ID                        = -15,
    KM_ERROR_INVALID_AUTHORIZATION_TIMEOUT          = -16,
    KM_ERROR_UNSUPPORTED_KEY_FORMAT                 = -17,
    KM_ERROR_INCOMPATIBLE_KEY_FORMAT                = -18,
    KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM   = -19, /* For PKCS8 & PKCS12 */
    KM_ERROR_UNSUPPORTED_KEY_VERIFICATION_ALGORITHM = -20, /* For PKCS8 & PKCS12 */
    KM_ERROR_INVALID_INPUT_LENGTH                   = -21,
    KM_ERROR_KEY_EXPORT_OPTIONS_INVALID             = -22,
    KM_ERROR_DELEGATION_NOT_ALLOWED                 = -23,
    KM_ERROR_KEY_NOT_YET_VALID                      = -24,
    KM_ERROR_KEY_EXPIRED                            = -25,
    KM_ERROR_KEY_USER_NOT_AUTHENTICATED             = -26,
    KM_ERROR_OUTPUT_PARAMETER_NULL                  = -27,
    KM_ERROR_INVALID_OPERATION_HANDLE               = -28,
    KM_ERROR_INSUFFICIENT_BUFFER_SPACE              = -29,
    KM_ERROR_VERIFICATION_FAILED                    = -30,
    KM_ERROR_TOO_MANY_OPERATIONS                    = -31,
    KM_ERROR_UNEXPECTED_NULL_POINTER                = -32,
    KM_ERROR_INVALID_KEY_BLOB                       = -33,
    KM_ERROR_IMPORTED_KEY_NOT_ENCRYPTED             = -34,
    KM_ERROR_IMPORTED_KEY_DECRYPTION_FAILED         = -35,
    KM_ERROR_IMPORTED_KEY_NOT_SIGNED                = -36,
    KM_ERROR_IMPORTED_KEY_VERIFICATION_FAILED       = -37,
    KM_ERROR_INVALID_ARGUMENT                       = -38,
    KM_ERROR_UNSUPPORTED_TAG                        = -39,
    KM_ERROR_INVALID_TAG                            = -40,
    KM_ERROR_MEMORY_ALLOCATION_FAILED               = -41,
    KM_ERROR_IMPORT_PARAMETER_MISMATCH              = -44,
    KM_ERROR_SECURE_HW_ACCESS_DENIED                = -45,
    KM_ERROR_OPERATION_CANCELLED                    = -46,
    KM_ERROR_CONCURRENT_ACCESS_CONFLICT             = -47,
    KM_ERROR_SECURE_HW_BUSY                         = -48,
    KM_ERROR_SECURE_HW_COMMUNICATION_FAILED         = -49,
    KM_ERROR_UNSUPPORTED_EC_FIELD                   = -50,
    KM_ERROR_MISSING_NONCE                          = -51,
    KM_ERROR_INVALID_NONCE                          = -52,
    KM_ERROR_MISSING_MAC_LENGTH                     = -53,
    KM_ERROR_KEY_RATE_LIMIT_EXCEEDED                = -54,
    KM_ERROR_CALLER_NONCE_PROHIBITED                = -55,
    KM_ERROR_KEY_MAX_OPS_EXCEEDED                   = -56,
    KM_ERROR_INVALID_MAC_LENGTH                     = -57,
    KM_ERROR_MISSING_MIN_MAC_LENGTH                 = -58,
    KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH             = -59,
    KM_ERROR_UNSUPPORTED_KDF                        = -60,
    KM_ERROR_UNSUPPORTED_EC_CURVE                   = -61,
    KM_ERROR_KEY_REQUIRES_UPGRADE                   = -62,
    KM_ERROR_ATTESTATION_CHALLENGE_MISSING          = -63,
    KM_ERROR_KEYMASTER_NOT_CONFIGURED               = -64,
    KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING     = -65,
    KM_ERROR_CANNOT_ATTEST_IDS                      = -66,
    KM_ROLLBACK_RESISTANCE_UNAVAILABLE              = -67,
    KM_HARDWARE_TYPE_UNAVAILABLE                    = -68,
    KM_PROOF_OF_PRESENCE_REQUIRED                   = -69,
    KM_CONCURRENT_PROOF_OF_PRESENCE_REQUESTED       = -70,
    KM_NO_USER_CONFIRMATION                         = -71,
    KM_DEVICE_LOCKED                                = -72,

    KM_ERROR_UNIMPLEMENTED    = -100,
    KM_ERROR_VERSION_MISMATCH = -101,

    /*
     * Additional error codes may be added by implementations, but implementers should coordinate
     * with Google to avoid code collision.
     */
    KM_ERROR_UNKNOWN_ERROR = -1000,
} keymaster_error_t;

#define SEED_SIZE  32
#define NONCE_SIZE 32
#define MAC_SIZE   32
/* Convenience functions for manipulating keymaster tag types */
/*
 * HmacSharingParameters holds the data used in the process of establishing a shared HMAC key
 * between multiple Keymaster instances.  Sharing parameters are returned in this struct by
 * getHmacSharingParameters() and send to computeSharedHmac().  See the named methods in IKeymaster
 * for details of usage.
 */
typedef struct {
    /*
     * Either empty or contains a persistent value that is associated with the pre-shared HMAC
     * agreement key (see documentation of computeSharedHmac in @4.0::IKeymaster).  It is either
     * empty or 32 bytes in length.
     */
    uint8_t seed[SEED_SIZE];

    /*
     * A 32-byte value which is guaranteed to be different each time
     * getHmacSharingParameters() is called.  Probabilistic uniqueness (i.e. random) is acceptable,
     * though a stronger uniqueness guarantee (e.g. counter) is recommended where possible.
     */
    uint8_t nonce[NONCE_SIZE];
} keymaster_hmac_sharing_parameters_t;

/*
 * VerificationToken enables one Keymaster instance to validate authorizations for another.  See
 * verifyAuthorizations() in IKeymaster for details.
 */
typedef struct {
    /* The operation handle, used to ensure freshness. */
    uint64_t challenge;

    /*
     * The current time of the secure environment that generates the VerificationToken.  This can be
     * checked against auth tokens generated by the same secure environment, which avoids needing to
     * synchronize clocks.
     */
    uint64_t timestamp;

    /*
     * A list of the parameters verified.  Empty if the only parameters verified are time-related.
     * In that case the timestamp is the payload.
     */
    keymaster_key_param_set_t parameters_verified;

    /* SecurityLevel of the secure environment that generated the token.  */
    keymaster_security_level_t security_level;

    /*
     * 32-byte HMAC-SHA256 of the above values, computed as:
     *
     *    HMAC(H,
     *         "Auth Verification" || challenge || timestamp || security_level || parameters_verified)
     *
     * where:
     *
     *   ``HMAC'' is the shared HMAC key (see computeSharedHmac() in IKeymaster).
     *
     *   ``||'' represents concatenation
     *
     * The representation of challenge and timestamp is as 64-bit unsigned integers in big-endian
     * order.  security_level is represented as a 32-bit unsigned integer in big-endian order.
     *
     * If parameters_verified is non-empty, the representation of parameters_verified is an ASN.1 DER
     * encoded representation of the values.  The ASN.1 schema used is the AuthorizationList schema
     * from the Keystore attestation documentation.  If parameters_verified is empty, it is simply
     * omitted from the HMAC computation.
     */
    uint8_t mac[MAC_SIZE];
} keymaster_verification_token_t;

#define TAG_GET_TYPE_SHIFT 28

static inline keymaster_tag_type_t keymaster_tag_get_type(keymaster_tag_t tag)
{
    return (keymaster_tag_type_t)(tag & (0xF << TAG_GET_TYPE_SHIFT));
}

static inline uint32_t keymaster_tag_mask_type(keymaster_tag_t tag)
{
    return (uint32_t)(tag & 0x0FFFFFFF);
}

static inline bool keymaster_tag_type_valid(keymaster_tag_type_t type)
{
    bool check = (type == KM_INVALID || type == KM_ENUM || type == KM_ENUM_REP || type == KM_UINT ||
        type == KM_UINT_REP || type == KM_ULONG || type == KM_DATE || type == KM_BOOL ||
        type == KM_BIGNUM || type == KM_BYTES || type == KM_ULONG_REP);
    return check;
}

static inline int km_tag_compare(keymaster_tag_t a, keymaster_tag_t b)
{
    return (a < b) ? -1 : ((a > b) ? 1 : 0);
}

typedef struct {
    uint32_t src;
    uint32_t dest;
} keymaster_uint2uint;

#define if_log(cond, fmt, args...)  do { if (cond)    \
            tloge("%s : " fmt "", ERROR_TAG, ##args); \
    } while (0);

#define check_if_unlock_failed_only_printf(ret_unlock)  do {                              \
        if ((ret_unlock) != TEE_SUCCESS)                                                  \
            tloge("pthread_mutex_unlock failed. ret=0x%x\n", ret_unlock);  } while (0)

#define km_buffer_vaild(in) ((in) == NULL || (in)->data_addr == NULL || (in)->data_length == 0)
/* KeyMaster configure status */
typedef enum {
    STATE_LOCKED   = 0,
    STATE_UNLOCKED = 1,
} state_lock_t;

typedef enum {
    STATE_UNCFG = 0,
    STATE_CFGED = 1,
} state_set_t;

struct cfg_state_t {
    char is_lock; /* 0-locked, 1-unlocked */
    char is_cfg;  /* 0-uncfg, 1-cfged */
};

uint32_t *get_passwd_flag(void);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */
#endif /* ANDROID_HARDWARE_KEYMASTER_DEFS_H */
