/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee cipher head file
 * Author: cipher group
 * Create: 2019-12-11
 */

#ifndef __HI_TEE_CIPHER__
#define __HI_TEE_CIPHER__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */
/*************************** structure definition ****************************/
/** \addtogroup      CIPHER */
/** @{ */ /** <!-- [CIPHER] */

/** max length of SM2, unit: word */
/** CNcomment: SM2数据长度，单位word */
#define HI_TEE_CIPHER_SM2_LEN_IN_WORD (8)

/** max length of SM2, unit: byte */
/** CNcomment: SM2数据长度，单位byte */
#define HI_TEE_CIPHER_SM2_LEN_IN_BYTE (HI_TEE_CIPHER_SM2_LEN_IN_WORD * 4)

/** AES IV length in word */
/** CNcomment: AES IV 长度，以字为单位 */
#define HI_TEE_CIPHER_AES_IV_LEN_IN_WORD (4)

/** SM4 IV length in word */
/** CNcomment: SM4 IV 长度，以字为单位 */
#define HI_TEE_CIPHER_SM4_IV_LEN_IN_WORD (4)

/** TDES IV length in word */
/** CNcomment: TDES IV 长度，以字为单位 */
#define HI_TEE_CIPHER_TDES_IV_LEN_IN_WORD (2)

/** encryption/decryption type selecting */
/** CNcomment:CIPHER加解密类型选择 */
typedef enum {
    HI_TEE_CIPHER_TYPE_NORMAL = 0x0,
    /**< Create normal channel */ /**< CNcomment: 创建普通通道 */
    HI_TEE_CIPHER_TYPE_MAX,
    HI_TEE_CIPHER_TYPE_INVALID = 0xffffffff,
} hi_tee_cipher_type;

/** cipher algorithm */
/** CNcomment:CIPHER加密算法 */
typedef enum {
    HI_TEE_CIPHER_ALG_3DES = 0x0, /**< 3DES algorithm */ /**< CNcomment: 3DES算法 */
    HI_TEE_CIPHER_ALG_AES = 0x1,  /**< Advanced encryption standard (AES) algorithm */ /**< CNcomment: AES算法 */
    HI_TEE_CIPHER_ALG_SM4 = 0x2,  /**< SM4 algorithm */ /**< CNcomment: SM4算法 */
    HI_TEE_CIPHER_ALG_DMA = 0x3,  /**< DMA copy */ /**< CNcomment: DMA拷贝 */
    HI_TEE_CIPHER_ALG_MAX = 0x4,
    HI_TEE_CIPHER_ALG_INVALID = 0xffffffff,
} hi_tee_cipher_alg;

/** cipher work mode */
/** CNcomment:CIPHER工作模式 */
typedef enum {
    /**< Electronic codebook (ECB) mode, ECB has been considered insecure and it isrecommended not to use it. */
    HI_TEE_CIPHER_WORK_MODE_ECB,    /**< CNcomment:ECB模式,ECB被认为是不安全算法，建议不要使用它。 */
    HI_TEE_CIPHER_WORK_MODE_CBC,    /**< Cipher block chaining (CBC) mode */ /**< CNcomment:CBC模式 */
    HI_TEE_CIPHER_WORK_MODE_CFB,    /**< Cipher feedback (CFB) mode */ /**< CNcomment:CFB模式 */
    HI_TEE_CIPHER_WORK_MODE_OFB,    /**< Output feedback (OFB) mode */ /**< CNcomment:OFB模式 */
    HI_TEE_CIPHER_WORK_MODE_CTR,    /**< Counter (CTR) mode */ /**< CNcomment:CTR模式 */
    HI_TEE_CIPHER_WORK_MODE_CCM,    /**< Counter (CCM) mode */ /**< CNcomment:CCM模式 */
    HI_TEE_CIPHER_WORK_MODE_GCM,    /**< Counter (GCM) mode */ /**< CNcomment:GCM模式 */
    HI_TEE_CIPHER_WORK_MODE_CBC_CTS,  /**< Cipher block chaining CipherStealing mode */ /**< CNcomment:CBC-CTS模式 */
    HI_TEE_CIPHER_WORK_MODE_MAX,
    HI_TEE_CIPHER_WORK_MODE_INVALID = 0xffffffff,
} hi_tee_cipher_work_mode;

/** key length */
/** CNcomment: 密钥长度 */
typedef enum {
    HI_TEE_CIPHER_KEY_AES_128BIT = 0x0, /**< 128-bit key for the AES algorithm */ /**< CNcomment:AES运算方式下采用128bit密钥长度 */
    HI_TEE_CIPHER_KEY_AES_192BIT = 0x1, /**< 192-bit key for the AES algorithm */ /**< CNcomment:AES运算方式下采用192bit密钥长度 */
    HI_TEE_CIPHER_KEY_AES_256BIT = 0x2, /**< 256-bit key for the AES algorithm */ /**< CNcomment:AES运算方式下采用256bit密钥长度 */
    HI_TEE_CIPHER_KEY_DES_3KEY = 0x2,   /**< Three keys for the DES algorithm */ /**< CNcomment:DES运算方式下采用3个key */
    HI_TEE_CIPHER_KEY_DES_2KEY = 0x3,   /**< Two keys for the DES algorithm */ /**< CNcomment: DES运算方式下采用2个key */
    /**< default key length, DES-8, SM1-48, SM4-16 */
    HI_TEE_CIPHER_KEY_DEFAULT = 0x0,    /**< CNcomment: 默认Key长度，DES-8, SM1-48, SM4-16 */
    HI_TEE_CIPHER_KEY_LENGTH_MAX = 0x4,
    HI_TEE_CIPHER_KEY_INVALID = 0xffffffff,
} hi_tee_cipher_key_length;

/** cipher bit width */
/** CNcomment: 加密位宽 */
typedef enum _hi_tee_cipher_bit_width {
    HI_TEE_CIPHER_BIT_WIDTH_1BIT = 0x0,  /**< 1-bit width */ /**< CNcomment:1bit位宽 */
    HI_TEE_CIPHER_BIT_WIDTH_8BIT = 0x1,  /**< 8-bit width */ /**< CNcomment:8bit位宽 */
    HI_TEE_CIPHER_BIT_WIDTH_64BIT = 0x2,  /**< 64-bit width */ /**< CNcomment:64bit位宽 */
    HI_TEE_CIPHER_BIT_WIDTH_128BIT = 0x3, /**< 128-bit width */ /**< CNcomment:128bit位宽 */
    HI_TEE_CIPHER_BIT_WIDTH_MAX,
    HI_TEE_CIPHER_BIT_WIDTH_INVALID = 0xffffffff,
} hi_tee_cipher_bit_width;

/** structure of the cipher type */
/** CNcomment:加密类型结构 */
typedef struct {
    hi_tee_cipher_type cipher_type;  /* Cipher type */
    hi_bool is_create_keyslot;       /* Create keyslot or not */
} hi_tee_cipher_attr;
/** cipher iv change type */
/** CNcomment: IV变更类型 */
typedef enum {
   HI_TEE_CIPHER_IV_DO_NOT_CHANGE = 0, /* IV donot change, cipher only set IV at the the first time */
   HI_TEE_CIPHER_IV_CHANGE_ONE_PKG = 1, /* Cipher set IV for the first package */
   HI_TEE_CIPHER_IV_CHANGE_ALL_PKG = 2, /* Cipher set IV for each package */
   HI_TEE_CIPHER_IV_CIPHER_MAX,
} hi_tee_cipher_iv_change_type;

/** cipher control parameters */
/** CNcomment:加密控制参数变更标志 */
typedef struct {
    /**< initial vector change flag, 0-don't set, 1-set IV for first package, 2-set IV for each package */
    hi_tee_cipher_iv_change_type iv_change_flag;     /**< CNcomment:向量变更, 0-不设置，1-只设置第一个包，2-每个包都设置 */
} hi_tee_cipher_config_change_flag;

/** encryption/decryption type selecting */
/** CNcomment:CIPHER加解密类型选择 */
typedef enum {
    /**< encrypt/decrypt data from ree to ree */
    HI_TEE_CIPHER_DATA_DIR_REE2REE = 0x0,   /**< CNcomment: 加解密数据从REE侧到REE侧 */
    /**< encrypt/decrypt data from ree to tee */
    HI_TEE_CIPHER_DATA_DIR_REE2TEE = 0x1,   /**< CNcomment: 加解密数据从REE侧到TEE侧 */
    /**< encrypt/decrypt data from tee to ree */
    HI_TEE_CIPHER_DATA_DIR_TEE2REE = 0x2,   /**< CNcomment: 加解密数据从TEE侧到REE侧 */
    /**< encrypt/decrypt data from tee to tee */
    HI_TEE_CIPHER_DATA_DIR_TEE2TEE = 0x3,   /**< CNcomment: 加解密数据从TEE侧到TEE侧 */
    HI_TEE_CIPHER_DATA_DIR_MAX,
    HI_TEE_CIPHER_DATA_DIR_INVALID = 0xffffffff,
} hi_tee_cipher_data_dir;

/** structure of the cipher control information */
/** CNcomment:加密控制信息结构 */
typedef struct {
    hi_tee_cipher_alg alg; /**< cipher algorithm */             /**< CNcomment:加密算法 */
    hi_tee_cipher_work_mode work_mode; /**< operating mode */ /**< CNcomment:工作模式 */
    /**< parameter for special algorithm
        for AES, the pointer should point to hi_tee_cipher_config_aes;
        for AES_CCM or AES_GCM, the pointer should point to hi_tee_cipher_config_aes_ccm_gcm;
        for 3DES, the pointer should point to hi_tee_cipher_config_3des;
        for SM4, the pointer should point to hi_tee_cipher_config_sm4;
 */
    /**< CNcomment: 算法的专用参数
        对于 AES, 指针应指向 hi_tee_cipher_config_aes;
        对于 AES_CCM 或 AES_GCM, 指针应指向 hi_tee_cipher_config_aes_ccm_gcm;
        对于 3DES, 指针应指向 hi_tee_cipher_config_3des;
        对于 SM4, 指针应指向 hi_tee_cipher_config_sm4;
    */
    hi_void *param;
} hi_tee_cipher_config;

/** structure of the cipher AES control information */
/** CNcomment:AES加密控制信息结构 */
typedef struct {
    hi_u32 iv[HI_TEE_CIPHER_AES_IV_LEN_IN_WORD]; /**< initialization vector (IV) */           /**< CNcomment:初始向量 */
    hi_tee_cipher_bit_width bit_width; /**< bit width for encryption or decryption */       /**< CNcomment:加密或解密的位宽 */
    hi_tee_cipher_key_length key_len; /**< key length */        /**< CNcomment:密钥长度 */
    /**< control information exchange choices, we default all woulde be change except they have been in the choices */
    hi_tee_cipher_config_change_flag change_flags;  /**< CNcomment:控制信息变更选项，选项中没有标识的项默认全部变更 */
} hi_tee_cipher_config_aes;

/** structure of the cipher AES CCM/GCM control information */
/** CNcomment:AES CCM/GCM 加密控制信息结构 */
typedef struct {
    hi_u32 iv[HI_TEE_CIPHER_AES_IV_LEN_IN_WORD]; /**< initialization vector (IV) */    /**< CNcomment:初始向量 */
    hi_tee_cipher_key_length key_len; /**< key length */ /**< CNcomment:密钥长度 */
    /**< IV lenght for CCM/GCM, which is an element of {7, 8, 9, 10, 11, 12, 13} for CCM,
     * and is an element of [1-16] for GCM */
    hi_u32 iv_len; /**< CNcomment: CCM/GCM的IV长度，CCM的取值范围{7, 8, 9, 10, 11, 12, 13}， GCM的取值范围[1-16] */
    /**< tag lenght for CCM which is an element of {4,6,8,10,12,14,16} */
    hi_u32 tag_len; /**< CNcomment: CCM的TAG长度，取值范围{4,6,8,10,12,14,16} */
    hi_u32 a_len; /**< associated data for CCM and GCM */                     /**< CNcomment: CCM/GCM的关联数据长度 */
    hi_mem_handle a_buf_handle; /**< buffer handle of associated data for CCM and GCM */  /**< CNcomment: CCM/GCM的关联数据地址句柄 */
} hi_tee_cipher_config_aes_ccm_gcm;

/** structure of the cipher 3DES control information */
/** CNcomment:3DES加密控制信息结构 */
typedef struct {
    hi_u32 iv[HI_TEE_CIPHER_TDES_IV_LEN_IN_WORD]; /**< initialization vector (IV) */        /**< CNcomment:初始向量 */
    hi_tee_cipher_bit_width bit_width; /**< bit width for encryption or decryption */       /**< CNcomment:加密或解密的位宽 */
    hi_tee_cipher_key_length key_len; /**< key length */        /**< CNcomment:密钥长度 */
    /**< control information exchange choices, we default all woulde be change except they have been in the choices */
    hi_tee_cipher_config_change_flag change_flags;  /**< CNcomment:控制信息变更选项，选项中没有标识的项默认全部变更 */
} hi_tee_cipher_config_3des;

/** structure of the cipher SM4 control information */
/** CNcomment:SM4加密控制信息结构 */
typedef struct {
    hi_u32 iv[HI_TEE_CIPHER_SM4_IV_LEN_IN_WORD]; /**< initialization vector (IV) */         /**< CNcomment:初始向量 */
    /**< control information exchange choices, we default all woulde be change except they have been in the choices */
    hi_tee_cipher_config_change_flag change_flags; /**< CNcomment:控制信息变更选项，选项中没有标识的项默认全部变更 */
} hi_tee_cipher_config_sm4;

/** cipher data */
/** CNcomment:加解密数据 */
typedef struct {
    hi_mem_handle src_buf; /**< buffer handle of the original data */ /**< CNcomment:源数据地址句柄 */
    hi_mem_handle dest_buf; /**< buffer handle of the purpose data */   /**< CNcomment:目的数据地址句柄 */
    hi_u32 byte_length; /**< cigher data length */    /**< CNcomment:加解密数据长度 */
    hi_bool is_odd_key; /**< use odd key or even key */     /**< CNcomment:是否使用奇密钥 */
} hi_tee_cipher_data;

/** hash algrithm type */
/** CNcomment:哈希算法类型 */
typedef enum {
    HI_TEE_CIPHER_HASH_TYPE_SHA1 = 0x00,
    HI_TEE_CIPHER_HASH_TYPE_SHA224,
    HI_TEE_CIPHER_HASH_TYPE_SHA256,
    HI_TEE_CIPHER_HASH_TYPE_SHA384,
    HI_TEE_CIPHER_HASH_TYPE_SHA512,
    HI_TEE_CIPHER_HASH_TYPE_SM3 = 0x10,
    HI_TEE_CIPHER_HASH_TYPE_HMAC_SHA1 = 0x20,
    HI_TEE_CIPHER_HASH_TYPE_HMAC_SHA224,
    HI_TEE_CIPHER_HASH_TYPE_HMAC_SHA256,
    HI_TEE_CIPHER_HASH_TYPE_HMAC_SHA384,
    HI_TEE_CIPHER_HASH_TYPE_HMAC_SHA512,
    HI_TEE_CIPHER_HASH_TYPE_HMAC_SM3 = 0x30,
    HI_TEE_CIPHER_HASH_TYPE_MAX,
    HI_TEE_CIPHER_HASH_TYPE_INVALID = 0xffffffff,
} hi_tee_cipher_hash_type;

/** hash init struct input */
/** CNcomment:哈希算法初始化输入结构体 */
typedef struct {
    /**< hmac key, if NULL, the key will come from klad */
    hi_u8 *hmac_key; /**< CNcomment: HMAC密钥，如果为空，则密钥将来自KLAD */
    /**< hmac key len, if 0, the key will come from klad */
    hi_u32 hmac_key_len; /**< CNcomment: HMAC密钥长度，如果为0，则密钥将来自KLAD */
    hi_tee_cipher_hash_type hash_type; /**< hash type */ /**< CNcomment: HASH类型 */
} hi_tee_cipher_hash_attr;

/** PBKDF2 struct input */
/** CNcomment: PBKDF2密钥生成算法参数结构体 */
typedef struct {
    hi_u8 *hmac_key;
    hi_u32 hmac_key_len;
    hi_u8 *salt;
    hi_u32 slen;
    hi_u32 iteration_count;
    hi_u32 key_length;
} hi_tee_cipher_pbkdf2_param;

typedef enum {
    HI_TEE_CIPHER_RSA_ENC_SCHEME_NO_PADDING,   /**< without padding */ /**< CNcomment: 不填充 */
    /**< PKCS#1 block type 0 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_0,  /**< CNcomment: PKCS#1的block type 0填充方式 */
    /**< PKCS#1 block type 1 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_1,  /**< CNcomment: PKCS#1的block type 1填充方式 */
    /**< PKCS#1 block type 2 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_2,  /**< CNcomment: PKCS#1的block type 2填充方式 */
    /**< PKCS#1 RSAES-OAEP-SHA1 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA1,  /**< CNcomment: PKCS#1的RSAES-OAEP-SHA1填充方式 */
    /**< PKCS#1 RSAES-OAEP-SHA224 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA224,  /**< CNcomment: PKCS#1的RSAES-OAEP-SHA224填充方式 */
    /**< PKCS#1 RSAES-OAEP-SHA256 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA256,  /**< CNcomment: PKCS#1的RSAES-OAEP-SHA256填充方式 */
    /**< PKCS#1 RSAES-OAEP-SHA384 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA384,  /**< CNcomment: PKCS#1的RSAES-OAEP-SHA384填充方式 */
    /**< PKCS#1 RSAES-OAEP-SHA512 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA512,  /**< CNcomment: PKCS#1的RSAES-OAEP-SHA512填充方式 */
    /**< PKCS#1 RSAES-PKCS1_V1_5 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_PKCS1_V1_5,  /**< CNcomment: PKCS#1的PKCS1_V1_5填充方式 */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_MAX,
    HI_TEE_CIPHER_RSA_ENC_SCHEME_INVALID = 0xffffffff,
} hi_tee_cipher_rsa_enc_scheme;

typedef enum {
    /**< PKCS#1 RSASSA_PKCS1_V15_SHA1 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA1 = 0x100, /**< CNcomment: PKCS#1 RSASSA_PKCS1_V15_SHA1签名算法 */
    /**< PKCS#1 RSASSA_PKCS1_V15_SHA224 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA224,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_V15_SHA224签名算法 */
    /**< PKCS#1 RSASSA_PKCS1_V15_SHA256 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA256,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_V15_SHA256签名算法 */
    /**< PKCS#1 RSASSA_PKCS1_V15_SHA384 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA384,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_V15_SHA384签名算法 */
    /**< PKCS#1 RSASSA_PKCS1_V15_SHA512 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA512,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_V15_SHA512签名算法 */
    /**< PKCS#1 RSASSA_PKCS1_PSS_SHA1 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA1,         /**< CNcomment: PKCS#1 RSASSA_PKCS1_PSS_SHA1签名算法 */
    /**< PKCS#1 RSASSA_PKCS1_PSS_SHA224 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA224,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_PSS_SHA224签名算法 */
    /**< PKCS#1 RSASSA_PKCS1_PSS_SHA256 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA256,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_PSS_SHA256签名算法 */
    /**< PKCS#1 RSASSA_PKCS1_PSS_SHA1 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA384,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_PSS_SHA384签名算法 */
    /**< PKCS#1 RSASSA_PKCS1_PSS_SHA256 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA512,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_PSS_SHA512签名算法 */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_MAX,
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_INVALID = 0xffffffff,
} hi_tee_cipher_rsa_sign_scheme;

typedef struct {
    hi_u8 *n; /**< point to public modulus */    /**< CNcomment: 指向RSA公钥N的指针 */
    hi_u8 *e; /**< point to public exponent */    /**< CNcomment: 指向RSA公钥E的指针 */
    hi_u16 n_len; /**< length of public modulus, max value is 512_byte */ /**< CNcomment: RSA公钥N的长度, 最大为512_byte */
    hi_u16 e_len; /**< length of public exponent, max value is 512_byte */ /**< CNcomment: RSA公钥E的长度, 最大为512_byte */
} hi_tee_cipher_rsa_pub_key;

/** RSA private key struct */
/** CNcomment:RSA私钥结构体 */
typedef struct {
    hi_u8 *n; /**<  public modulus */     /**< CNcomment: 指向RSA公钥N的指针 */
    hi_u8 *e; /**<  public exponent */     /**< CNcomment: 指向RSA公钥E的指针 */
    hi_u8 *d; /**<  private exponent */     /**< CNcomment: 指向RSA私钥D的指针 */
    hi_u8 *p; /**<  1st prime factor */     /**< CNcomment: 指向RSA私钥P的指针 */
    hi_u8 *q; /**<  2nd prime factor */     /**< CNcomment: 指向RSA私钥Q的指针 */
    hi_u8 *dp; /**<  D % (P - 1) */    /**< CNcomment: 指向RSA私钥DP的指针 */
    hi_u8 *dq; /**<  D % (Q - 1) */    /**< CNcomment: 指向RSA私钥DQ的指针 */
    hi_u8 *qp; /**<  1 / (Q % P) */    /**< CNcomment: 指向RSA私钥QP的指针 */
    hi_u16 n_len; /**< length of public modulus */  /**< CNcomment: RSA公钥N的长度 */
    hi_u16 e_len; /**< length of public exponent */  /**< CNcomment: RSA公钥E的长度 */
    hi_u16 d_len; /**< length of private exponent */  /**< CNcomment: RSA私钥D的长度 */
    /**< length of 1st prime factor,should be half of n_len */
    hi_u16 p_len;   /**< CNcomment: RSA私钥P的长度，必须为n_len长度的1/2 */
    /**< length of 2nd prime factor,should be half of n_len */
    hi_u16 q_len;   /**< CNcomment: RSA私钥Q的长度，必须为n_len长度的1/2 */
    /**< length of D % (P - 1),should be half of n_len */
    hi_u16 dp_len;  /**< CNcomment: RSA私钥DP的长度，必须为n_len长度的1/2 */
    /**< length of D % (Q - 1),should be half of n_len */
    hi_u16 dq_len;  /**< CNcomment: RSA私钥DQ的长度，必须为n_len长度的1/2 */
    /**< length of 1 / (Q % P),should be half of n_len */
    hi_u16 qp_len;  /**< CNcomment: RSA私钥QP的长度，必须为n_len长度的1/2 */
} hi_tee_cipher_rsa_priv_key;

/** RSA public key encryption struct input */
/** CNcomment:RSA 公钥加解密算法参数结构体 */
typedef struct {
    hi_tee_cipher_rsa_enc_scheme enc_scheme; /** RSA encryption scheme */ /** CNcomment:RSA数据加解密算法策略 */
    hi_tee_cipher_rsa_pub_key pub_key; /** RSA private key struct */       /** CNcomment:RSA私钥结构体 */
} hi_tee_cipher_rsa_pub_enc_param;

/** RSA private key decryption struct input */
/** CNcomment:RSA 私钥解密算法参数结构体 */
typedef struct {
    hi_tee_cipher_rsa_enc_scheme enc_scheme; /** RSA encryption scheme */ /** CNcomment:RSA数据加解密算法 */
    hi_tee_cipher_rsa_priv_key priv_key; /** RSA private key struct */   /** CNcomment:RSA私钥结构体 */
} hi_tee_cipher_rsa_pri_enc_param;

/** RSA signature struct input */
/** CNcomment:RSA签名算法参数结构体 */
typedef struct {
    hi_tee_cipher_rsa_sign_scheme sign_scheme; /** RSA signature scheme */ /** CNcomment:RSA数据签名策略 */
    hi_tee_cipher_rsa_priv_key priv_key; /** RSA private key struct */    /** CNcomment:RSA私钥结构体 */
} hi_tee_cipher_rsa_sign_param;

/** RSA signature verify struct input */
/** CNcomment:RSA签名验证算法参数输入结构体 */
typedef struct {
    hi_tee_cipher_rsa_sign_scheme sign_scheme; /** RSA signature scheme */ /** CNcomment:RSA数据签名策略 */
    hi_tee_cipher_rsa_pub_key pub_key; /** RSA public key struct */        /** CNcomment:RSA公钥结构体 */
} hi_tee_cipher_rsa_verify_param;

/** rsa sign and verify data struct information */
/** CNcomment: rsa签名校验参数结构体 */
typedef struct {
    /** input context to be signature verification. */
    hi_u8 *input;       /** CNcomment:待签名验证的数据，如果hash_data不为空，则该该指针可以为空 */
    hi_u32 input_len;  /** length of input context to be signature. */ /** CNcomment:待签名验证的数据长度 */
    /** hash value of context,if NULL, let hash_data = Hash(context) automatically,its length depends on hash type,
     * it is 20 for sha1,28 for sha224,32 for sha256 or sm3,48 for sha384,64 for sha512. */
    hi_u8 *hash_data; /** CNcomment:待签名文本的HASH摘要，sha1为20，sha224为28，sha256为32，sha384为48，sha512为64。如果为空，则自动计算文本的HASH摘要 */
    /** message of signature, its buffer length must not less than the width of RSA Key N. */
    hi_u8 *sign;       /** CNcomment:签名信息, 它的缓冲区大小不能小于RSA密钥N的位宽 */
    hi_u32 *sign_len;  /** length of message of signature buffer. */ /** CNcomment:签名信息的数据长度 */
} hi_tee_cipher_rsa_sign_verify_data;

/** SM2 signature struct input */
/** CNcomment: SM2签名算法参数结构体 */
typedef struct {
    hi_u32 d[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 px[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 py[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u8 *id;
    hi_u16 id_len;
} hi_tee_cipher_sm2_sign_param;

/** SM2 signature verify struct input */
/** CNcomment: SM2签名验证算法参数输入结构体 */
typedef struct {
    hi_u32 px[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 py[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u8 *id;
    hi_u16 id_len;
} hi_tee_cipher_sm2_verify_param;

/** sm2 sign and verify data struct information */
/** CNcomment: sm2签名校验参数结构体 */
typedef struct {
    /** input context to be signature，maybe null. */
    hi_u8 *msg;       /** CNcomment:待签名的数据, 如果pu8HashData不为空，则该指针可以为空 */
    hi_u32 msg_len;  /** length of input context to be signature. */ /** CNcomment:待签名的数据长度 */
    hi_u8 *sign_r;    /** The R value of the signature result,its length is 32. */ /** CNcomment:签名结果的R值，长度32 */
    hi_u8 *sign_s;    /** The S value of the signature result,its length is 32. */ /** CNcomment:签名结果的S值，长度32 */
    hi_u32 sign_buf_len;  /** the length of the signature result,its length is 32. */ /** CNcomment:签名结果长度 */
} hi_tee_cipher_sm2_sign_verify_data;

/** SM2 publuc key encryption struct input */
/** CNcomment: SM2公钥加密算法参数结构体 */
typedef struct {
    hi_u32 px[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 py[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
} hi_tee_cipher_sm2_enc_param;

/** SM2 private key decryption struct input */
/** CNcomment: SM2私钥解密算法参数结构体 */
typedef struct {
    hi_u32 d[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
} hi_tee_cipher_sm2_dec_param;

/** SM2 key generate struct input */
/** CNcomment: SM2密钥生成算法参数结构体 */
typedef struct {
    hi_u32 d[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 px[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 py[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
} hi_tee_cipher_sm2_key;

/** CENC subsample expansion struct input */
/** CNcomment: CENC subsample 参数扩展结构体 */
typedef struct {
    hi_u32 clear_header_len; /* !< the length of clear header */            /**< CNcomment: 透明头部长度 */
    hi_u32 pay_load_len; /* !< the length of payload */                /**< CNcomment: 有效负责的长度 */
    /* !< the length of encrypt data in each pattern that should be a multiple of 16 */
    hi_u32 payload_pattern_encrypt_len;  /**< CNcomment: 各个pattern中密文的长度，必须是16的整数倍 */
    /* !< the length of clear data in each pattern that should be a multiple of 16 */
    hi_u32 payload_pattern_clear_len;    /**< CNcomment: 各个pattern中明文的长度，必须是16的整数倍 */
    /* !< the offset of first pattern that should be a multiple of 16 */
    hi_u32 payload_pattern_offset_len;   /**< CNcomment: 首个pattern中的数据偏移量，必须是16的整数倍 */
    /**< initial vector change flag, 0-don't set, 1-set IV for first package */
    hi_u32 iv_change;                    /**< CNcomment:初始向量变更, 0-不设置，1-设置第一个包 */
    hi_u32 iv[HI_TEE_CIPHER_AES_IV_LEN_IN_WORD]; /**< initial vector */      /**< CNcomment: 初始向量 */
} hi_tee_cipher_subsample;

typedef struct {
    hi_bool is_odd_key;
    hi_u32 first_block_offset;
    hi_tee_cipher_subsample *subsample;
    hi_u32 subsample_num;
    hi_tee_cipher_data_dir data_dir;
} hi_tee_cipher_cenc_param;

typedef hi_void (*hi_tee_cipher_done_callback_func)(
    hi_handle cipher, hi_s32 result, hi_void *user_data, hi_u32 user_data_size);

typedef struct {
    hi_tee_cipher_done_callback_func func_symc_done;
    hi_void *user_data;
    hi_u32 user_data_size;
} hi_tee_cipher_done_callback;

/** cenc decrypt data struct information */
/** CNcomment: cenc解密参数结构体 */
typedef struct {
    hi_mem_handle src_buf;;                   /** Physical address of the source data. */ /** CNcomment:源数据地址句柄 */
    hi_mem_handle dest_buf;                  /** Physical address of the target data. */ /** CNcomment:目的数据地址句柄 */
    hi_u32 byte_length;                      /** Length of the decrypted data. */ /** CNcomment:加密数据长度 */
    hi_tee_cipher_done_callback *symc_done; /** Callback struct, When this structure pointer is not empty, the interface
    will immediately return and call the callback function to notify the user when the calculation is complete,
    but if the structure is empty, the interface will block until the calculation is complete.. */
    /** CNcomment:计算完成时的回调函数结构体，当该结构体指针非空时，该接口会立即返回并在计算完成时调用此回调函数通知用户，
    但如果该结构体为空，则该接口会阻塞直到计算完成为止 */
} hi_tee_cenc_decrypt_data;

/** dh gen key data struct information */
/** CNcomment: 生成dh key参数结构体 */
typedef struct {
    /** Buffer containing the DH generator g used for the operation. The caller ensures it ispadded with leading
     * zeros if the effective size of this key is smaller than the key_size. */
    hi_u8 *g;          /** CNcomment:DH的g参数，长度不足Key的大小，前面补0 */
    /** Buffer containing the DH generator p used for the operation. The caller ensures it is padded with leading
     * zeros if the effective size of this key is smaller than the key_size. */
    hi_u8 *p;          /** CNcomment:DH的p参数，长度不足Key的大小，前面补0 */
    /** Buffer containing an optional input private key from which the public has to be generated.  The caller
     * ensures it is padded with leading zeros if the effective size of this key is smaller than the u32KeySize.
     * If no private key is provided as input (\c input_priv_key=NULL), function generates a random private key
     * and stores it in pu8OutputPrivKey this buffer. */
    hi_u8 *input_priv_key;    /** CNcomment:DH的私钥，长度不足Key的大小，前面补0, 如果为空指针，该函数将生成一个私钥放到output_priv_key中 */
    /** Buffer where to write the generated private key, in case no private key is providedas input
     * (input_priv_key==NULL). It must be padded with leading zeros if the effective size of the private
     * key is smaller than the buffer size. */
    hi_u8 *output_priv_key;  /** CNcomment:DH的私钥，长度不足Key的大小，前面补0, 如果input_priv_key为空指针，该函数将生成一个私钥放到这个buffer中 */
    hi_u8 *pub_key;   /** public key. */ /** CNcomment:DH的公钥，长度不足Key的大小，前面补0 */
    hi_u32 key_size;  /** DH key size. */ /** CNcomment:DH密钥长度 */
} hi_tee_cipher_dh_gen_key_data;

/** @} */ /** <!-- ==== structure definition end ==== */

/* API declaration */
/** \addtogroup      CIPHER */
/** @{ */ /** <!-- [CIPHER] */
/* ---CIPHER--- */
/**
\brief  init the cipher device.  CNcomment:初始化CIPHER设备。 CNend
\attention \n
this API is used to start the cipher device.
CNcomment:调用此接口初始化CIPHER设备。 CNend
\param N/A                                                                      CNcomment:无 CNend
\retval ::HI_SUCCESS  call this API successful.                                 CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE  call this API fails.                                      CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_FAILED_INIT  the cipher device fails to be initialized. CNcomment:CIPHER设备初始化失败 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_init(hi_void);

/**
\brief  deinit the cipher device.
CNcomment:\brief  去初始化CIPHER设备。 CNend
\attention \n
this API is used to stop the cipher device. if this API is called repeatedly, HI_SUCCESS is returned,
but only the first operation takes effect.
CNcomment:调用此接口关闭CIPHER设备。重复关闭返回成功，第一次起作用。 CNend
\param N/A                                                                      CNcomment:无 CNend
\retval ::HI_SUCCESS  call this API successful.                                 CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE  call this API fails.                                      CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.         CNcomment:CIPHER设备未初始化 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_deinit(hi_void);

/**
\brief obtain a cipher handle for encryption and decryption.
CNcomment：创建一路cipher句柄。 CNend
\param[in] cipher attributes                                                    CNcomment:cipher 属性。 CNend
\param[out] cipher cipher handle                                              CNcomment:CIPHER句柄。 CNend
\retval ::HI_SUCCESS call this API successful.                                  CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE call this API fails.                                       CNcomment: API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.         CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  the pointer is null.                     CNcomment:指针参数为空 CNend
\retval ::HI_ERR_CIPHER_FAILED_GETHANDLE  the cipher handle fails to be obtained, because there are no available
cipher handles. CNcomment: 获取CIPHER句柄失败，没有空闲的CIPHER句柄 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_create(hi_handle *cipher, const hi_tee_cipher_attr *cipher_attr);

/**
\brief destroy the existing cipher handle. CNcomment:销毁已存在的CIPHER句柄。 CNend
\attention \n
this API is used to destroy existing cipher handles.
CNcomment:调用此接口销毁已经创建的CIPHER句柄。 CNend
\param[in] cipher cipher handle                                                CNcomment:CIPHER句柄。 CNend
\retval ::HI_SUCCESS  call this API successful.                                 CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE  call this API fails.                                      CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.         CNcomment:CIPHER设备未初始化 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_destroy(hi_handle cipher);

/**
\brief configures the cipher control information.
CNcomment:\brief 配置CIPHER控制信息。 CNend
\attention \n
before encryption or decryption, you must call this API to configure the cipher control information.
the first 64-bit data and the last 64-bit data should not be the same when using TDES algorithm.
support AES/DES/3DES/SM1/SM4 algorithm, support ECB/CBC/CTR/OFB/CFB/CCM/GCM mode.
CNcomment:进行加密解密前必须先使用此接口配置CIPHER的控制信息。
使用TDES算法时，输入密钥的前后64 bit数据不能相同。
支持 AES/DES/3DES/SM1/SM4 算法, ECB/CBC/CTR/OFB/CFB/CCM/GCM 模式.CNend
\param[in] cipher cipher handle.                                                CNcomment:CIPHER句柄 CNend
\param[in] cipher_config cipher control information.                            CNcomment:CIPHER控制信息 CNend
\retval ::HI_SUCCESS call this API succussful.                                  CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE call this API fails.                                       CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.         CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  the pointer is null.                     CNcomment:指针参数为空 CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  the parameter is invalid.                 CNcomment:参数错误 CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  the handle is invalid.                  CNcomment:句柄非法 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_set_config(hi_handle cipher, const hi_tee_cipher_config *cipher_config);

/**
\brief Get the cipher control information.
CNcomment:\brief 获取CIPHER控制信息。 CNend
\param[in] cipher Cipher handle.                                                CNcomment:CIPHER句柄 CNend
\param[in] cipher_config Cipher control information.                            CNcomment:CIPHER控制信息 CNend
\retval ::HI_SUCCESS Call this API successful.                                  CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Call this API fails.                                       CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.         CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  The pointer is null.                     CNcomment:指针参数为空 CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  The parameter is invalid.                 CNcomment:参数错误 CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  The handle is invalid.                  CNcomment:句柄非法 CNend
\see \n
N/A
*/
hi_s32 hi_tee_cipher_get_config(hi_handle cipher, const hi_tee_cipher_config *cipher_config);


/**
\brief Get a keyslot handle which banding to cipher handle.
CNcomment：获取绑定到Cipher句柄的KeySlot句柄。 CNend

\param[in]  cipher cipher handle                                                CNcomment:CIPHER句柄。 CNend
\param[out] keyslot KeySlot handle                                              CNcomment:KeySlot句柄。 CNend
\retval ::HI_SUCCESS Call this API successful.                                  CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Call this API fails.                                       CNcomment: API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.         CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  The pointer is null.                     CNcomment:指针参数为空 CNend
\retval ::HI_ERR_CIPHER_FAILED_GETHANDLE  The keyslot handle fails to be obtained. CNcomment: 获取KeySlot句柄失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_cipher_get_keyslot_handle(hi_handle cipher, hi_handle *keyslot);

/**
\brief Attach a keyslot handle  to cipher handle.
CNcomment：绑定Cipher句柄和KeySlot句柄。 CNend
\param[in]  cipher cipher handle                                                CNcomment:CIPHER句柄。 CNend
\param[out] keyslot KeySlot handle                                              CNcomment:KeySlot句柄。 CNend
\retval ::HI_SUCCESS Call this API successful.                                  CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Call this API fails.                                       CNcomment: API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.         CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  The pointer is null.                     CNcomment:指针参数为空 CNend
\retval ::HI_ERR_CIPHER_FAILED_GETHANDLE  The keyslot handle fails to be obtained. CNcomment: 获取KeySlot句柄失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_cipher_attach_keyslot(hi_handle cipher, hi_handle keyslot);

/**
\brief Detach a keyslot handle from cipher handle.
CNcomment：解除Cipher句柄和KeySlot句柄绑定。 CNend
\param[in]  cipher cipher handle                                                CNcomment:CIPHER句柄。 CNend
\param[out] keyslot KeySlot handle                                              CNcomment:KeySlot句柄。 CNend
\retval ::HI_SUCCESS Call this API successful.                                  CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Call this API fails.                                       CNcomment: API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.         CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  The pointer is null.                     CNcomment:指针参数为空 CNend
\retval ::HI_ERR_CIPHER_FAILED_GETHANDLE  The keyslot handle fails to be obtained. CNcomment: 获取KeySlot句柄失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_cipher_detach_keyslot(hi_handle cipher,  hi_handle keyslot);

/**
\brief performs encryption.
CNcomment:\brief 进行加密。 CNend

\attention \n
this API is used to perform encryption by using the cipher module.
the length of the encrypted data should be a multiple of 8 in TDES mode and 16 in AES mode.
after this operation,the result will affect next operation.if you want to remove vector,
you need to config IV(config ctrl->change_flags.bit1_iv with 1) by transfering hi_tee_cipher_set_config.
CNcomment:使用CIPHER进行加密操作。TDES模式下加密的数据长度应当是8的倍数，AES下应当是16的倍数。本次操作完成后，此次操作的向量运算结果会作用于下一次操作，
如果要清除向量，需要在下次加密操作之前调用hi_tee_cipher_config_handle重新配置IV(需要设置ctrl->change_flags.bit1_iv为1)。 CNend
\param[in] cipher cipher handle                                                CNcomment:CIPHER句柄 CNend
\param[in] src_buf buffer handle of the source data                    CNcomment:源数据地址句柄 CNend
\param[in] dest_buf buffer handle address of the target data                      CNcomment:目的数据地址句柄 CNend
\param[in] byte_length   Length of the encrypted data                          CNcomment:加密数据长度 CNend
\param[in] data_dir data                                                       CNcomment:数据传输方向。 CNend
retval ::HI_SUCCESS   call this API successful.                                CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE   call this API fails.                                    CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.        CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  the parameter is invalid.                CNcomment:参数错误 CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  the handle is invalid.                 CNcomment:句柄非法 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_encrypt(hi_handle cipher,
                             hi_mem_handle src_buf,
                             hi_mem_handle dest_buf,
                             hi_u32 byte_length,
                             hi_tee_cipher_data_dir data_dir);

/**
\brief performs decryption.
CNcomment:\brief 进行解密 CNend
\attention \n
This API is used to perform decryption by using the cipher module.
The length of the decrypted data should be a multiple of 8 in TDES mode and 16 in AES mode. Besides, the length can
not be bigger than 0xFFFFF.After this operation, the result will affect next operation.If you want to remove vector,
you need to config IV(config pstCtrl->stChangeFlags.bit1IV with 1) by transfering HI_UNF_CIPHER_ConfigHandle.
CNcomment:使用CIPHER进行解密操作。TDES模式下解密的数据长度应当是8的倍数，AES下应当是16的倍数。此外，解密数据长度不能长于0xFFFFF。
本次操作完成后，此次操作的向量运算结果会作用于下一次操作，如果要清除向量，需要在下次解密操作之前调用HI_UNF_CIPHER_ConfigHandle
重新配置IV(需要设置pstCtrl->stChangeFlags.bit1IV为1)。 CNend
\param[in] cipher Cipher handle.                                               CNcomment:CIPHER句柄 CNend
\param[in] src_buf buffer handle of the source data.                   CNcomment:源数据地址句柄 CNend
\param[in] dest_buf buffer handle of the target data.                     CNcomment:目的数据地址句柄 CNend
\param[in] byte_length Length of the decrypted data                            CNcomment:解密数据长度 CNend
\param[in] data_dir data  direction                                            CNcomment:数据传输方向。 CNend
\retval ::HI_SUCCESS Call this API successful.                                 CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Call this API fails.                                      CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.        CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  The parameter is invalid.                CNcomment:参数错误 CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  The handle is invalid.                 CNcomment:句柄非法 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_decrypt(hi_handle cipher,
                             hi_mem_handle src_buf,
                             hi_mem_handle dest_buf,
                             hi_u32 byte_length,
                             hi_tee_cipher_data_dir data_dir);

/**
\brief encrypt multiple packaged data.
CNcomment:\brief 进行多个包数据的加密。 CNend
\attention \n
You can not encrypt more than 128 data package one time. When HI_ERR_CIPHER_BUSY return, the data package you send
will not be deal, the custmer should decrease the number of data package or run cipher again.Note:When encrypting
more than one packaged data, every one package will be calculated using initial vector configured by
HI_UNF_CIPHER_ConfigHandle.Previous result will not affect the later result.
CNcomment:每次加密的数据包个数最多不能超过128个。返回HI_ERR_CIPHER_BUSY的时候，送入数据包一个也不会被处理，用户需要减少送入的数据包的数量或者再次尝试加密。
注意: 对于多个包的操作，每个包都使用HI_UNF_CIPHER_ConfigHandle配置的向量进行运算，前一个包的向量运算结果不会作用于下一个包的运算，每个包都是独立运算的。
前一次函数调用的结果也不会影响后一次函数调用的运算结果。 CNend
\param[in] cipher cipher handle                                                CNcomment:CIPHER句柄。 CNend
\param[in] data_pkg data package ready for cipher                              CNcomment:待加密的数据包。 CNend
\param[in] data_pkg_num  number of package ready for cipher                    CNcomment:待加密的数据包个数。 CNend
\param[in] data_dir data  direction                                            CNcomment:数据传输方向。 CNend
\retval ::HI_SUCCESS  Call this API successful.                                CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE  Call this API fails.                                     CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  cipher device have not been initialized      CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  parameter error                          CNcomment:参数错误 CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  handle invalid                         CNcomment:句柄非法 CNend
\retval ::HI_ERR_CIPHER_BUSY  hardware is busy, it can not deal with all data package once time
CNcomment:硬件正忙，无法一次性处理全部的数据包 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_encrypt_multi(hi_handle cipher,
                                   const hi_tee_cipher_data *data_pkg,
                                   hi_u32 data_pkg_num,
                                   hi_tee_cipher_data_dir data_dir);

/**
\brief decrypt multiple packaged data.
CNcomment:\brief 进行多个包数据的解密。 CNend
\attention \n
You can not decrypt more than 128 data package one time.When HI_ERR_CIPHER_BUSY return, the data package you send
will not be deal, the custmer should decrease the number of data package or run cipher again.Note:When decrypting
more than one packaged data, every one package will be calculated using initial vector configured by
HI_UNF_CIPHER_ConfigHandle.Previous result will not affect the later result.
CNcomment:每次解密的数据包个数最多不能超过128个。返回HI_ERR_CIPHER_BUSY的时候，送入数据包一个也不会被处理，用户需要减少送入的数据包的数量或者再次尝试解密。
注意: 对于多个包的操作，每个包都使用HI_UNF_CIPHER_ConfigHandle配置的向量进行运算，前一个包的向量运算结果不会作用于下一个包的运算，每个包都是独立运算的，
前一次函数调用的结果也不会影响后一次函数调用的运算结果。 CNend
\param[in] cipher cipher handle                                               CNcomment:CIPHER句柄。 CNend
\param[in] data_pkg data package ready for cipher                             CNcomment:待解密的数据包。 CNend
\param[in] data_pkg_num  number of package ready for cipher                   CNcomment:待解密的数据包个数。 CNend
\param[in] data_dir data  direction                                           CNcomment:数据传输方向。 CNend
\retval ::HI_SUCCESS  Call this API succussful.                               CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE  Call this API fails.                                    CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  cipher device have not been initialized     CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  parameter error                         CNcomment:参数错误 CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  handle invalid                        CNcomment:句柄非法 CNend
\retval ::HI_ERR_CIPHER_BUSY  hardware is busy, it can not deal with all data package once time
CNcomment:硬件正忙，无法一次性处理全部的数据包 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_decrypt_multi(hi_handle cipher,
                                   const hi_tee_cipher_data *data_pkg,
                                   hi_u32 data_pkg_num,
                                   hi_tee_cipher_data_dir data_dir);

/**
\brief CENC decryption a ciphertext.
CNcomment: CENC格式解密一段密文。 CNend
\attention \n
this API is used to perform decryption ciphertext base on CENC format.
CNcomment:使用CIPHER进行CENC格式解密操作。 CNend
\param[in] cipher cipher handle                                                   CNcomment:CIPHER句柄 CNend
\param[in] cenc key for cipher decryption,its length should be 16.                CNcomment:CIPHER 解密密钥,长度为16. CNend
\param[in] in_phy_addr physical address of the source data                        CNcomment:源数据物理地址 CNend
\param[in] out_phy_addr physical address of the target data                       CNcomment:目的数据物理地址 CNend
\param[in] byte_length   Length of the decrypted data                             CNcomment:加密数据长度 CNend
\param[in] symc_done callback struct, when this structure pointer is not empty, the interface will immediately
           return and call the callback function to notify the user when the calculation is complete,
           but if the structure is empty, the interface will block until the calculation is complete.
           CNcomment:计算完成时的回调函数结构体，当该结构体指针非空时，该接口会立即返回并在计算完成时
           调用此回调函数通知用户，但如果该结构体为空，则该接口会阻塞直到计算完成为止 CNend
\retval ::HI_SUCCESS  call this API succussful.                                    CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE  call this API fails.                                         CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.            CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  the parameter is invalid.                    CNcomment:参数错误 CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  the handle is invalid.                     CNcomment:句柄非法 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_cenc_decrypt(hi_handle cipher, const hi_tee_cipher_cenc_param *param,
                                  hi_tee_cenc_decrypt_data *cenc_decrypt_data);

/**
\brief get the tag data of CCM/GCM.
CNcomment:\brief 获取CCM/GCM的TAG数据。 CNend
\attention \n
This API is used to get the tag data of CCM/GCM.
\param[in] cipher cipher handle                                                 CNcomment:CIPHER句柄。 CNend
\param[out] tag tag data of CCM/GCM                                             CNcomment:TAG指针 CNend
\param[in/out] tag_len tag data length of CCM/GCM, the input should be 16 now.  CNcomment:TAG数据长度，输入需设置为16 CNend
\retval ::HI_SUCCESS  Call this API succussful.                                 CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE  Call this API fails.                                      CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.         CNcomment:CIPHER设备未初始化 CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  The parameter is invalid.                 CNcomment:参数错误 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_get_tag(hi_handle cipher, hi_u8 *tag, hi_u32 *tag_len);

/**
\brief get a word of random number.
CNcomment:\brief 获取一个字的随机数。 CNend
\attention \n
this API is used to obtain the random number from the hardware.
CNcomment: 调用此接口用于获取随机数。 CNend
\param[out] random_number point to the random number.                      CNcomment:随机数数值。 CNend
\retval ::HI_SUCCESS  call this API successful.                            CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                                 CNcomment: API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_get_random_number(hi_u32 *random_number);

/**
\brief get the random bytes.
CNcomment:\brief 获取随机数。 CNend
\attention \n
this API is used to obtain the random number from the hardware.
CNcomment:调用此接口用于获取随机数。 CNend
\param[out] random_number point to the random number.                      CNcomment:随机数数值。 CNend
\param[in]  bytes size of the random bytes.                                CNcomment:随机数大小。 CNend
\retval ::HI_SUCCESS  call this API successful.                            CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                                 CNcomment: API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_get_multi_random_bytes(hi_u32 bytes, hi_u8 *random_byte);

/**
\brief init the hash module, if other program is using the hash module, the API will return failure.
CNcomment:\brief 初始化HASH模块，如果有其他程序正在使用HASH模块，返回失败状态。 CNend
\attention \n
N/A
\param[in] attr: the hash calculating structure input.                      CNcomment:用于计算hash的结构体参数 CNend
\param[out] hash: the output hash handle.                                   CNcomment:输出的hash句柄 CNend
\retval ::HI_SUCCESS  call this API successful.                             CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                                  CNcomment: API系统调用失败 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_hash_init(hi_tee_cipher_hash_attr *hash_attr, hi_handle *hash);

/**
\brief calculate the hash, if the size of the data to be calculated is very big and the DDR ram is not enough,
this API can calculate the data one block by one block. attention: the input block length must be 64bytes
aligned except for the last block.
CNcomment:\brief 计算hash值，如果需要计算的数据量比较大，该接口可以实现一个block一个block的计算，避免数据量比较大的情况下，内存不足的问题。
特别注意，除了最后一个block，前面的每一轮输入的长度都必须是64字节对齐。CNend
\attention \n
N/A
\param[in] hashandl:  hash handle.                                        CNcomment:hash句柄。 CNend
\param[in] input_data:  the input data buffer.                            CNcomment:输入数据缓冲 CNend
\param[in] input_data_len:  the input data length, attention: the block length input
must be 64bytes aligned except the last block!
CNcomment:输入数据的长度。重要： 输入数据块的长度必须是64字节对齐，最后一个block无此限制。 CNend
\retval ::HI_SUCCESS  call this API successful.                           CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                                CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_hash_update(hi_handle hash, const hi_u8 *input_data, hi_u32 input_data_len);

/**
\brief get the final hash value, after calculate all of the data, call this API to get the final hash value and close
the handle.if there is some reason need to interrupt the calculation, this API should also be call to close the handle.
CNcomment:获取hash值，在计算完所有的数据后，调用这个接口获取最终的hash值，该接口同时会关闭hash句柄。如果在计算过程中，需要中断计算，也必须调用该接口关闭hash句柄。 CNend
\attention \n
N/A
\param[in] hash:  hash handle.                                          CNcomment:hash句柄。  CNend
\param[out] output_hash:  the final output hash value，and its length depends on hash type,
it is 20 for sha1,28 for sha224,32 for sha256 or sm3,48 for sha384,64 for sha512.
\param[in/out] hash_len:  The final output buffer lengrh.
CNcomment:输出的hash值，长度由hash类型决定，sha1时输出长度20，sha224输出长度28，sha256和上sm3输出长度32，sha384输出长度48，sha512输出长度64。 CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_hash_final(hi_handle hash, hi_u8 *hash_buf, hi_u32 *hash_len);

/**
\brief RSA encryption a plaintext with a RSA public key.
CNcomment:使用RSA公钥加密一段明文。 CNend
\attention \n
N/A
\param[in] param:   encryption struct.                                  CNcomment:加密属性结构体。 CNend
\param[in] input：   input data to be encryption                        CNcomment: 待加密的数据。 CNend
\param[out] input_len:   length of input data to be encryption          CNcomment: 待加密的数据长度。 CNend
\param[out] output： output data to be encryption, its buffer length must not less than the width of RSA key N.
CNcomment: 加密结果数据, 它的缓冲区大小不能小于RSA密钥N的位宽。 CNend
\param[in/out] output_len: length of output buffer to be                CNcomment: 加密结果的数据长度。 CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_public_encrypt(hi_tee_cipher_rsa_pub_enc_param *param,
                                        hi_u8 *input, hi_u32 input_len,
                                        hi_u8 *output, hi_u32 *output_len);

/**
\brief RSA decryption a ciphertext with a RSA private key.
CNcomment:使用RSA私钥解密一段密文。 CNend
\attention \n
N/A
\param[in] param:   decryption struct.                                  CNcomment: 公钥解密属性结构体。 CNend
\param[in] input：   input data to be decryption                        CNcomment: 待解密的数据。 CNend
\param[out] input_len:   length of input data to be decryption          CNcomment: 待解密的数据长度。 CNend
\param[out] output： output buffer to storage decryption data, its length must not less than the width of RSA key N.
CNcomment: 解密结果数据, 它的缓冲区大小不能小于RSA密钥N的位宽。 CNend
\param[in/out] output_len: length of output buffer to be decryption     CNcomment: 解密结果的数据长度。 CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_private_decrypt(hi_tee_cipher_rsa_pri_enc_param *param,
                                         hi_u8 *input, hi_u32 input_len,
                                         hi_u8 *output, hi_u32 *output_len);

/**
\brief RSA encryption a plaintext with a RSA private key.
CNcomment:使用RSA私钥加密一段明文。 CNend
\attention \n
N/A
\param[in] param:   encryption struct.                                  CNcomment:加密属性结构体。 CNend
\param[in] input：   input data to be encryption                        CNcomment: 待加密的数据。 CNend
\param[out] input_len:   length of input data to be encryption          CNcomment: 待加密的数据长度。 CNend
\param[out] output： output data to be encryption, its buffer length must not less than the width of RSA key N.
CNcomment: 加密结果数据, 它的缓冲区大小不能小于RSA密钥N的位宽。 CNend
\param[in/out] output_len: length of output buffer to be encryption     CNcomment: 加密结果的数据长度。 CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_private_encrypt(hi_tee_cipher_rsa_pri_enc_param *param,
                                         hi_u8 *input, hi_u32 input_len,
                                         hi_u8 *output, hi_u32 *output_len);

/**
\brief RSA decryption a ciphertext with a RSA public key.
CNcomment:使用RSA公钥解密一段密文。 CNend
\attention \n
N/A
\param[in] rsa_verify:   decryption struct.                               CNcomment: 解密属性结构体。 CNend
\param[in] input：   input data to be decryption                          CNcomment: 待解密的数据。 CNend
\param[out] input_len:   length of input data to be decryption            CNcomment: 待解密的数据长度。 CNend
\param[out] output： output buffer to storage decryption data, its length must not less than the width of RSA key N
CNcomment: 解密结果数据, 它的缓冲区大小不能小于RSA密钥N的位宽。 CNend
\param[in/out] output_len: length of output buffer to be decryption     CNcomment: 解密结果的数据长度。 CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_public_decrypt(hi_tee_cipher_rsa_pub_enc_param *param,
                                        hi_u8 *input, hi_u32 input_len,
                                        hi_u8 *output, hi_u32 *output_len);

/**
\brief RSA signature a context with appendix, where a signer’s RSA private key is used.
CNcomment:使用RSA私钥签名一段文本。 CNend
\attention \n
N/A
\param[in] param:      signature struct.                                CNcomment: 签名属性结构体。 CNend
\param[in] input：       input context to be signature，maybe null
CNcomment: 待签名的数据, 如果hasdata不为空，则该指空可以为空。 CNend
\param[in] input_len:        length of input context to be signature
CNcomment: 待签名的数据长度。 CNend
\param[in] hash_data：    hash value of context,if NULL, let hasdata = hash(context) automatically,its length
depends on hash type, it is 20 for sha1,28 for sha224,32 for sha256 or sm3,48 for sha384,64 for sha512.
ncomment: 待签名文本的HASH摘要，
CNcomment:输出的hash摘要，长度由hash类型决定，sha1时输出长度20，sha224输出长度28，sha256输出长度32，sha384输出长度48，
sha512输出长度64。如果为空，则自动计算文本的HASH摘要。 CNend
\param[out] out_sign：    output message of signature, its buffer length must not less than the width of RSA key N.
CNcomment: 签名信息, 它的缓冲区大小不能小于RSA密钥N的位宽。 CNend
\param[in/out] out_sign_len: length of message of signature buffer      CNcomment: 签名信息的数据长度。 CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_sign(hi_tee_cipher_rsa_sign_param *param, hi_tee_cipher_rsa_sign_verify_data *rsa_sign_data);

/**
\brief RSA signature verification a context with appendix, where a signer’s RSA public key is used.
CNcomment:使用RSA公钥签名验证一段文本。 CNend
\attention \n
N/A
\param[in] rsa_verify:    signature verification struct.                CNcomment: 签名验证属性结构体。 CNend
\param[in] input：       input context to be signature verification，maybe null
CNcomment: 待签名验证的数据, 如果hasdata不为空，则该指空可以为空。 CNend
\param[in] input_len:        length of input context to be signature    CNcomment: 待签名验证的数据长度。 CNend
\param[in] hash_data：    hash value of context,if NULL, let hasdata = hash(context) automatically,its length
depends on hash type, it is 20 for sha1,28 for sha224,32 for sha256 or sm3,48 for sha384,64 for sha512.
ncomment: 待签名文本的HASH摘要，
CNcomment:输出的hash摘要，长度由hash类型决定，sha1时输出长度20，sha224输出长度28，sha256输出长度32，sha384输出长度48，sha512输出长度64。
ncomment: 待签名文本的HASH摘要，如果为空，则自动计算文本的HASH摘要。 CNend
\param[in] in_sign：      message of signature, its buffer length must not less than the width of RSA key N.
CNcomment: 签名信息, 它的缓冲区大小不能小于RSA密钥N的位宽。 CNend
\param[in] in_sign_len:   length of message of signature                       CNcomment: 签名信息的数据长度。 CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_verify(
    hi_tee_cipher_rsa_verify_param *rsa_verify, hi_tee_cipher_rsa_sign_verify_data *rsa_verify_data);

/**
\brief SM2 signature a context with appendix, where a signer’s SM2 private key is used.
CNcomment:使用SM2私钥签名一段文本。 CNend
\attention \n
N/A
\param[in] sm2_sign:      signature struct.                                    CNcomment: 签名属性结构体。 CNend
\param[in/out] sm2_sign_data:  signature data struct                           CNcomment: 签名计算的数据结构体。 CNend
\param[in] sing_buf_len:  length of signature buffer                           CNcomment: 待签名的数据长度。 CNend
\retval ::HI_SUCCESS  call this API succussful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_sm2_sign(hi_tee_cipher_sm2_sign_param *param, hi_tee_cipher_sm2_sign_verify_data *sm2_sign_data);

/**
\brief SM2 signature verification a context with appendix, where a signer’s SM2 public key is used.
CNcomment:使用SM2公钥签名验证一段文本。 CNend
\attention \n
N/A
\param[in] param:    signature verification struct.                         CNcomment: 签名验证属性结构体。 CNend
\param[in/out] sm2_verify_data:  signature data struct                      CNcomment: 签名计算的数据结构体。 CNend
\retval ::HI_SUCCESS  call this API succussful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_sm2_verify(
    hi_tee_cipher_sm2_verify_param *param, const hi_tee_cipher_sm2_sign_verify_data *sm2_verify_data);

/**
\brief SM2 encryption a plaintext with a RSA public key.
CNcomment:使用SM2公钥加密一段明文。 CNend
\attention \n
N/A
\param[in] param:   encryption struct.                                  CNcomment: 加密属性结构体。 CNend
\param[in] msg：     input data to be encryption                        CNcomment: 待加密的数据。 CNend
\param[in] msg_len:   length of input data to be encryption             CNcomment: 待加密的数据长度。 CNend
\param[out] c：      output data to be encryption                       CNcomment: 加密结果数据。 CNend
\param[in/out] c_len:   length of output buffer to be encryption        CNcomment: 加密结果的数据长度。 CNend
\retval ::HI_SUCCESS  call this API succussful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_sm2_encrypt(hi_tee_cipher_sm2_enc_param *param, hi_u8 *msg, hi_u32 msg_len, hi_u8 *c,
                                 hi_u32 *c_len);

/**
\brief RSA decryption a ciphertext with a SM2 private key.
CNcomment:使用SM2私钥解密一段密文。 CNend
\attention \n
N/A
\param[in] param:   decryption struct.                                   CNcomment: 公钥解密属性结构体。 CNend
\param[in] c：       input data to be decryption                         CNcomment: 待解密的数据。 CNend
\param[out] c_len:    length of input data to be decryption              CNcomment: 待解密的数据长度。 CNend
\param[out] msg：    output data to be decryption                        CNcomment: 解密结果数据。 CNend
\param[in/out] msg_len: length of output buffer to be decryption         CNcomment: 解密结果的数据长度。 CNend
\retval ::HI_SUCCESS  call this API succussful.                          CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                               CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_sm2_decrypt(hi_tee_cipher_sm2_dec_param *param, hi_u8 *c, hi_u32 c_len, hi_u8 *msg,
                                 hi_u32 *msg_len);

/**
\brief generate a SM2 key pair.
CNcomment:生成一个SM2密钥对。 CNend
\attention \n
N/A
\param[out] sm2_key:   key pair struct.                                 CNcomment: SM2密钥对。 CNend
\retval ::HI_SUCCESS  call this API succussful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_sm2_gen_key(hi_tee_cipher_sm2_key *sm2_key);

/**
\brief calculate a key of PBKDF2
CNcomment: 计算PBKDF2密钥 CNend
\attention \n
N/A
\param[in] param:  the PBKDF2 key calculating structure input.        CNcomment:PBKDF2密钥输入结构。 CNend
\param[out] output:  the final output hash value, its buffer length must not less than param->key_length.
CNcomment:输出的PBKDF2密钥, 它的缓冲区大小不能小于param->key_length。   CNend
\retval ::HI_SUCCESS  call this API successful.                      CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                           CNcomment:API系统调用失败。 CNend

\see \n
N/A
 */
hi_s32 hi_tee_cipher_pbkdf2(const hi_tee_cipher_pbkdf2_param *param, hi_u8 *output, hi_u32 output_len);

/**
\brief generate diffie-hellman public/private key pair from g and p parameters.
the public key is equal to g^x mod p,where x is random number considered as the private key.
CNcomment: 生成DH公私密钥对。 CNend
\attention \n
N/A
\param[in/out] param: dh gen key data struct            CNcomment: DH生成密钥数据结构体. CNend
\retval ::HI_SUCCESS  call this API succussful.         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_dh_gen_key(hi_tee_cipher_dh_gen_key_data *param);

/**
\brief compute ECDH shared secret key. this key corresponds to the X coordinates of the computed P point.
CNcomment: 计算ECC DH共享密钥。 CNend
\attention \n
N/A
\param[in] params:  elliptic curve domain parameters. the caller is in charge padding each buffer with leading zeros
if the effective size of the domain parameter conveyed is smaller than params->key_size.
CNcomment: ECC椭圆曲线参数，长度不足key的大小，前面补0。 CNend
\param[in] priv_key: buffer containing the ECDH private key. the caller ensures it is padded with leading zeros if
the effective size of this key is smaller than the key_size.
CNcomment: ECDH私钥，长度不足key的大小，前面补0。 CNend
\param[in] other_pub_key: buffer containing the other peer's public key. it is padded by the caller with leading
zeros if the effective size of the public key is smaller than the buffer size.
CNcomment: 对方的ECDH公钥的X坐标，长度不足key的大小，前面补0。 CNend
\param[out] shared_secret:  buffer where to write the computed shared secret. the caller ensures it is padded with
leading zeros if the effective size of this key is smaller than the key_size.
CNcomment: ECDH共享密钥，长度不足key的大小，前面补0。 CNend
\retval ::HI_SUCCESS  call this API succussful.                         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:API系统调用失败。 CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_dh_compute_key(hi_u8 *p, hi_u8 *priv_key, hi_u8 *other_pub_key,
                                    hi_u8 *shared_secret, hi_u32 key_size);


/** @} */ /** <!-- ==== API declaration end ==== */
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_TEE_CIPHER__ */
