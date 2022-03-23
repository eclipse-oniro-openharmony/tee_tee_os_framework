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
/** CNcomment: SM2���ݳ��ȣ���λword */
#define HI_TEE_CIPHER_SM2_LEN_IN_WORD (8)

/** max length of SM2, unit: byte */
/** CNcomment: SM2���ݳ��ȣ���λbyte */
#define HI_TEE_CIPHER_SM2_LEN_IN_BYTE (HI_TEE_CIPHER_SM2_LEN_IN_WORD * 4)

/** AES IV length in word */
/** CNcomment: AES IV ���ȣ�����Ϊ��λ */
#define HI_TEE_CIPHER_AES_IV_LEN_IN_WORD (4)

/** SM4 IV length in word */
/** CNcomment: SM4 IV ���ȣ�����Ϊ��λ */
#define HI_TEE_CIPHER_SM4_IV_LEN_IN_WORD (4)

/** TDES IV length in word */
/** CNcomment: TDES IV ���ȣ�����Ϊ��λ */
#define HI_TEE_CIPHER_TDES_IV_LEN_IN_WORD (2)

/** encryption/decryption type selecting */
/** CNcomment:CIPHER�ӽ�������ѡ�� */
typedef enum {
    HI_TEE_CIPHER_TYPE_NORMAL = 0x0,
    /**< Create normal channel */ /**< CNcomment: ������ͨͨ�� */
    HI_TEE_CIPHER_TYPE_MAX,
    HI_TEE_CIPHER_TYPE_INVALID = 0xffffffff,
} hi_tee_cipher_type;

/** cipher algorithm */
/** CNcomment:CIPHER�����㷨 */
typedef enum {
    HI_TEE_CIPHER_ALG_3DES = 0x0, /**< 3DES algorithm */ /**< CNcomment: 3DES�㷨 */
    HI_TEE_CIPHER_ALG_AES = 0x1,  /**< Advanced encryption standard (AES) algorithm */ /**< CNcomment: AES�㷨 */
    HI_TEE_CIPHER_ALG_SM4 = 0x2,  /**< SM4 algorithm */ /**< CNcomment: SM4�㷨 */
    HI_TEE_CIPHER_ALG_DMA = 0x3,  /**< DMA copy */ /**< CNcomment: DMA���� */
    HI_TEE_CIPHER_ALG_MAX = 0x4,
    HI_TEE_CIPHER_ALG_INVALID = 0xffffffff,
} hi_tee_cipher_alg;

/** cipher work mode */
/** CNcomment:CIPHER����ģʽ */
typedef enum {
    /**< Electronic codebook (ECB) mode, ECB has been considered insecure and it isrecommended not to use it. */
    HI_TEE_CIPHER_WORK_MODE_ECB,    /**< CNcomment:ECBģʽ,ECB����Ϊ�ǲ���ȫ�㷨�����鲻Ҫʹ������ */
    HI_TEE_CIPHER_WORK_MODE_CBC,    /**< Cipher block chaining (CBC) mode */ /**< CNcomment:CBCģʽ */
    HI_TEE_CIPHER_WORK_MODE_CFB,    /**< Cipher feedback (CFB) mode */ /**< CNcomment:CFBģʽ */
    HI_TEE_CIPHER_WORK_MODE_OFB,    /**< Output feedback (OFB) mode */ /**< CNcomment:OFBģʽ */
    HI_TEE_CIPHER_WORK_MODE_CTR,    /**< Counter (CTR) mode */ /**< CNcomment:CTRģʽ */
    HI_TEE_CIPHER_WORK_MODE_CCM,    /**< Counter (CCM) mode */ /**< CNcomment:CCMģʽ */
    HI_TEE_CIPHER_WORK_MODE_GCM,    /**< Counter (GCM) mode */ /**< CNcomment:GCMģʽ */
    HI_TEE_CIPHER_WORK_MODE_CBC_CTS,  /**< Cipher block chaining CipherStealing mode */ /**< CNcomment:CBC-CTSģʽ */
    HI_TEE_CIPHER_WORK_MODE_MAX,
    HI_TEE_CIPHER_WORK_MODE_INVALID = 0xffffffff,
} hi_tee_cipher_work_mode;

/** key length */
/** CNcomment: ��Կ���� */
typedef enum {
    HI_TEE_CIPHER_KEY_AES_128BIT = 0x0, /**< 128-bit key for the AES algorithm */ /**< CNcomment:AES���㷽ʽ�²���128bit��Կ���� */
    HI_TEE_CIPHER_KEY_AES_192BIT = 0x1, /**< 192-bit key for the AES algorithm */ /**< CNcomment:AES���㷽ʽ�²���192bit��Կ���� */
    HI_TEE_CIPHER_KEY_AES_256BIT = 0x2, /**< 256-bit key for the AES algorithm */ /**< CNcomment:AES���㷽ʽ�²���256bit��Կ���� */
    HI_TEE_CIPHER_KEY_DES_3KEY = 0x2,   /**< Three keys for the DES algorithm */ /**< CNcomment:DES���㷽ʽ�²���3��key */
    HI_TEE_CIPHER_KEY_DES_2KEY = 0x3,   /**< Two keys for the DES algorithm */ /**< CNcomment: DES���㷽ʽ�²���2��key */
    /**< default key length, DES-8, SM1-48, SM4-16 */
    HI_TEE_CIPHER_KEY_DEFAULT = 0x0,    /**< CNcomment: Ĭ��Key���ȣ�DES-8, SM1-48, SM4-16 */
    HI_TEE_CIPHER_KEY_LENGTH_MAX = 0x4,
    HI_TEE_CIPHER_KEY_INVALID = 0xffffffff,
} hi_tee_cipher_key_length;

/** cipher bit width */
/** CNcomment: ����λ�� */
typedef enum _hi_tee_cipher_bit_width {
    HI_TEE_CIPHER_BIT_WIDTH_1BIT = 0x0,  /**< 1-bit width */ /**< CNcomment:1bitλ�� */
    HI_TEE_CIPHER_BIT_WIDTH_8BIT = 0x1,  /**< 8-bit width */ /**< CNcomment:8bitλ�� */
    HI_TEE_CIPHER_BIT_WIDTH_64BIT = 0x2,  /**< 64-bit width */ /**< CNcomment:64bitλ�� */
    HI_TEE_CIPHER_BIT_WIDTH_128BIT = 0x3, /**< 128-bit width */ /**< CNcomment:128bitλ�� */
    HI_TEE_CIPHER_BIT_WIDTH_MAX,
    HI_TEE_CIPHER_BIT_WIDTH_INVALID = 0xffffffff,
} hi_tee_cipher_bit_width;

/** structure of the cipher type */
/** CNcomment:�������ͽṹ */
typedef struct {
    hi_tee_cipher_type cipher_type;  /* Cipher type */
    hi_bool is_create_keyslot;       /* Create keyslot or not */
} hi_tee_cipher_attr;
/** cipher iv change type */
/** CNcomment: IV������� */
typedef enum {
   HI_TEE_CIPHER_IV_DO_NOT_CHANGE = 0, /* IV donot change, cipher only set IV at the the first time */
   HI_TEE_CIPHER_IV_CHANGE_ONE_PKG = 1, /* Cipher set IV for the first package */
   HI_TEE_CIPHER_IV_CHANGE_ALL_PKG = 2, /* Cipher set IV for each package */
   HI_TEE_CIPHER_IV_CIPHER_MAX,
} hi_tee_cipher_iv_change_type;

/** cipher control parameters */
/** CNcomment:���ܿ��Ʋ��������־ */
typedef struct {
    /**< initial vector change flag, 0-don't set, 1-set IV for first package, 2-set IV for each package */
    hi_tee_cipher_iv_change_type iv_change_flag;     /**< CNcomment:�������, 0-�����ã�1-ֻ���õ�һ������2-ÿ���������� */
} hi_tee_cipher_config_change_flag;

/** encryption/decryption type selecting */
/** CNcomment:CIPHER�ӽ�������ѡ�� */
typedef enum {
    /**< encrypt/decrypt data from ree to ree */
    HI_TEE_CIPHER_DATA_DIR_REE2REE = 0x0,   /**< CNcomment: �ӽ������ݴ�REE�ൽREE�� */
    /**< encrypt/decrypt data from ree to tee */
    HI_TEE_CIPHER_DATA_DIR_REE2TEE = 0x1,   /**< CNcomment: �ӽ������ݴ�REE�ൽTEE�� */
    /**< encrypt/decrypt data from tee to ree */
    HI_TEE_CIPHER_DATA_DIR_TEE2REE = 0x2,   /**< CNcomment: �ӽ������ݴ�TEE�ൽREE�� */
    /**< encrypt/decrypt data from tee to tee */
    HI_TEE_CIPHER_DATA_DIR_TEE2TEE = 0x3,   /**< CNcomment: �ӽ������ݴ�TEE�ൽTEE�� */
    HI_TEE_CIPHER_DATA_DIR_MAX,
    HI_TEE_CIPHER_DATA_DIR_INVALID = 0xffffffff,
} hi_tee_cipher_data_dir;

/** structure of the cipher control information */
/** CNcomment:���ܿ�����Ϣ�ṹ */
typedef struct {
    hi_tee_cipher_alg alg; /**< cipher algorithm */             /**< CNcomment:�����㷨 */
    hi_tee_cipher_work_mode work_mode; /**< operating mode */ /**< CNcomment:����ģʽ */
    /**< parameter for special algorithm
        for AES, the pointer should point to hi_tee_cipher_config_aes;
        for AES_CCM or AES_GCM, the pointer should point to hi_tee_cipher_config_aes_ccm_gcm;
        for 3DES, the pointer should point to hi_tee_cipher_config_3des;
        for SM4, the pointer should point to hi_tee_cipher_config_sm4;
 */
    /**< CNcomment: �㷨��ר�ò���
        ���� AES, ָ��Ӧָ�� hi_tee_cipher_config_aes;
        ���� AES_CCM �� AES_GCM, ָ��Ӧָ�� hi_tee_cipher_config_aes_ccm_gcm;
        ���� 3DES, ָ��Ӧָ�� hi_tee_cipher_config_3des;
        ���� SM4, ָ��Ӧָ�� hi_tee_cipher_config_sm4;
    */
    hi_void *param;
} hi_tee_cipher_config;

/** structure of the cipher AES control information */
/** CNcomment:AES���ܿ�����Ϣ�ṹ */
typedef struct {
    hi_u32 iv[HI_TEE_CIPHER_AES_IV_LEN_IN_WORD]; /**< initialization vector (IV) */           /**< CNcomment:��ʼ���� */
    hi_tee_cipher_bit_width bit_width; /**< bit width for encryption or decryption */       /**< CNcomment:���ܻ���ܵ�λ�� */
    hi_tee_cipher_key_length key_len; /**< key length */        /**< CNcomment:��Կ���� */
    /**< control information exchange choices, we default all woulde be change except they have been in the choices */
    hi_tee_cipher_config_change_flag change_flags;  /**< CNcomment:������Ϣ���ѡ�ѡ����û�б�ʶ����Ĭ��ȫ����� */
} hi_tee_cipher_config_aes;

/** structure of the cipher AES CCM/GCM control information */
/** CNcomment:AES CCM/GCM ���ܿ�����Ϣ�ṹ */
typedef struct {
    hi_u32 iv[HI_TEE_CIPHER_AES_IV_LEN_IN_WORD]; /**< initialization vector (IV) */    /**< CNcomment:��ʼ���� */
    hi_tee_cipher_key_length key_len; /**< key length */ /**< CNcomment:��Կ���� */
    /**< IV lenght for CCM/GCM, which is an element of {7, 8, 9, 10, 11, 12, 13} for CCM,
     * and is an element of [1-16] for GCM */
    hi_u32 iv_len; /**< CNcomment: CCM/GCM��IV���ȣ�CCM��ȡֵ��Χ{7, 8, 9, 10, 11, 12, 13}�� GCM��ȡֵ��Χ[1-16] */
    /**< tag lenght for CCM which is an element of {4,6,8,10,12,14,16} */
    hi_u32 tag_len; /**< CNcomment: CCM��TAG���ȣ�ȡֵ��Χ{4,6,8,10,12,14,16} */
    hi_u32 a_len; /**< associated data for CCM and GCM */                     /**< CNcomment: CCM/GCM�Ĺ������ݳ��� */
    hi_mem_handle a_buf_handle; /**< buffer handle of associated data for CCM and GCM */  /**< CNcomment: CCM/GCM�Ĺ������ݵ�ַ��� */
} hi_tee_cipher_config_aes_ccm_gcm;

/** structure of the cipher 3DES control information */
/** CNcomment:3DES���ܿ�����Ϣ�ṹ */
typedef struct {
    hi_u32 iv[HI_TEE_CIPHER_TDES_IV_LEN_IN_WORD]; /**< initialization vector (IV) */        /**< CNcomment:��ʼ���� */
    hi_tee_cipher_bit_width bit_width; /**< bit width for encryption or decryption */       /**< CNcomment:���ܻ���ܵ�λ�� */
    hi_tee_cipher_key_length key_len; /**< key length */        /**< CNcomment:��Կ���� */
    /**< control information exchange choices, we default all woulde be change except they have been in the choices */
    hi_tee_cipher_config_change_flag change_flags;  /**< CNcomment:������Ϣ���ѡ�ѡ����û�б�ʶ����Ĭ��ȫ����� */
} hi_tee_cipher_config_3des;

/** structure of the cipher SM4 control information */
/** CNcomment:SM4���ܿ�����Ϣ�ṹ */
typedef struct {
    hi_u32 iv[HI_TEE_CIPHER_SM4_IV_LEN_IN_WORD]; /**< initialization vector (IV) */         /**< CNcomment:��ʼ���� */
    /**< control information exchange choices, we default all woulde be change except they have been in the choices */
    hi_tee_cipher_config_change_flag change_flags; /**< CNcomment:������Ϣ���ѡ�ѡ����û�б�ʶ����Ĭ��ȫ����� */
} hi_tee_cipher_config_sm4;

/** cipher data */
/** CNcomment:�ӽ������� */
typedef struct {
    hi_mem_handle src_buf; /**< buffer handle of the original data */ /**< CNcomment:Դ���ݵ�ַ��� */
    hi_mem_handle dest_buf; /**< buffer handle of the purpose data */   /**< CNcomment:Ŀ�����ݵ�ַ��� */
    hi_u32 byte_length; /**< cigher data length */    /**< CNcomment:�ӽ������ݳ��� */
    hi_bool is_odd_key; /**< use odd key or even key */     /**< CNcomment:�Ƿ�ʹ������Կ */
} hi_tee_cipher_data;

/** hash algrithm type */
/** CNcomment:��ϣ�㷨���� */
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
/** CNcomment:��ϣ�㷨��ʼ������ṹ�� */
typedef struct {
    /**< hmac key, if NULL, the key will come from klad */
    hi_u8 *hmac_key; /**< CNcomment: HMAC��Կ�����Ϊ�գ�����Կ������KLAD */
    /**< hmac key len, if 0, the key will come from klad */
    hi_u32 hmac_key_len; /**< CNcomment: HMAC��Կ���ȣ����Ϊ0������Կ������KLAD */
    hi_tee_cipher_hash_type hash_type; /**< hash type */ /**< CNcomment: HASH���� */
} hi_tee_cipher_hash_attr;

/** PBKDF2 struct input */
/** CNcomment: PBKDF2��Կ�����㷨�����ṹ�� */
typedef struct {
    hi_u8 *hmac_key;
    hi_u32 hmac_key_len;
    hi_u8 *salt;
    hi_u32 slen;
    hi_u32 iteration_count;
    hi_u32 key_length;
} hi_tee_cipher_pbkdf2_param;

typedef enum {
    HI_TEE_CIPHER_RSA_ENC_SCHEME_NO_PADDING,   /**< without padding */ /**< CNcomment: ����� */
    /**< PKCS#1 block type 0 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_0,  /**< CNcomment: PKCS#1��block type 0��䷽ʽ */
    /**< PKCS#1 block type 1 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_1,  /**< CNcomment: PKCS#1��block type 1��䷽ʽ */
    /**< PKCS#1 block type 2 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_BLOCK_TYPE_2,  /**< CNcomment: PKCS#1��block type 2��䷽ʽ */
    /**< PKCS#1 RSAES-OAEP-SHA1 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA1,  /**< CNcomment: PKCS#1��RSAES-OAEP-SHA1��䷽ʽ */
    /**< PKCS#1 RSAES-OAEP-SHA224 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA224,  /**< CNcomment: PKCS#1��RSAES-OAEP-SHA224��䷽ʽ */
    /**< PKCS#1 RSAES-OAEP-SHA256 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA256,  /**< CNcomment: PKCS#1��RSAES-OAEP-SHA256��䷽ʽ */
    /**< PKCS#1 RSAES-OAEP-SHA384 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA384,  /**< CNcomment: PKCS#1��RSAES-OAEP-SHA384��䷽ʽ */
    /**< PKCS#1 RSAES-OAEP-SHA512 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_OAEP_SHA512,  /**< CNcomment: PKCS#1��RSAES-OAEP-SHA512��䷽ʽ */
    /**< PKCS#1 RSAES-PKCS1_V1_5 padding */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_RSAES_PKCS1_V1_5,  /**< CNcomment: PKCS#1��PKCS1_V1_5��䷽ʽ */
    HI_TEE_CIPHER_RSA_ENC_SCHEME_MAX,
    HI_TEE_CIPHER_RSA_ENC_SCHEME_INVALID = 0xffffffff,
} hi_tee_cipher_rsa_enc_scheme;

typedef enum {
    /**< PKCS#1 RSASSA_PKCS1_V15_SHA1 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA1 = 0x100, /**< CNcomment: PKCS#1 RSASSA_PKCS1_V15_SHA1ǩ���㷨 */
    /**< PKCS#1 RSASSA_PKCS1_V15_SHA224 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA224,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_V15_SHA224ǩ���㷨 */
    /**< PKCS#1 RSASSA_PKCS1_V15_SHA256 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA256,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_V15_SHA256ǩ���㷨 */
    /**< PKCS#1 RSASSA_PKCS1_V15_SHA384 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA384,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_V15_SHA384ǩ���㷨 */
    /**< PKCS#1 RSASSA_PKCS1_V15_SHA512 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_V15_SHA512,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_V15_SHA512ǩ���㷨 */
    /**< PKCS#1 RSASSA_PKCS1_PSS_SHA1 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA1,         /**< CNcomment: PKCS#1 RSASSA_PKCS1_PSS_SHA1ǩ���㷨 */
    /**< PKCS#1 RSASSA_PKCS1_PSS_SHA224 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA224,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_PSS_SHA224ǩ���㷨 */
    /**< PKCS#1 RSASSA_PKCS1_PSS_SHA256 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA256,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_PSS_SHA256ǩ���㷨 */
    /**< PKCS#1 RSASSA_PKCS1_PSS_SHA1 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA384,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_PSS_SHA384ǩ���㷨 */
    /**< PKCS#1 RSASSA_PKCS1_PSS_SHA256 signature */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_RSASSA_PKCS1_PSS_SHA512,       /**< CNcomment: PKCS#1 RSASSA_PKCS1_PSS_SHA512ǩ���㷨 */
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_MAX,
    HI_TEE_CIPHER_RSA_SIGN_SCHEME_INVALID = 0xffffffff,
} hi_tee_cipher_rsa_sign_scheme;

typedef struct {
    hi_u8 *n; /**< point to public modulus */    /**< CNcomment: ָ��RSA��ԿN��ָ�� */
    hi_u8 *e; /**< point to public exponent */    /**< CNcomment: ָ��RSA��ԿE��ָ�� */
    hi_u16 n_len; /**< length of public modulus, max value is 512_byte */ /**< CNcomment: RSA��ԿN�ĳ���, ���Ϊ512_byte */
    hi_u16 e_len; /**< length of public exponent, max value is 512_byte */ /**< CNcomment: RSA��ԿE�ĳ���, ���Ϊ512_byte */
} hi_tee_cipher_rsa_pub_key;

/** RSA private key struct */
/** CNcomment:RSA˽Կ�ṹ�� */
typedef struct {
    hi_u8 *n; /**<  public modulus */     /**< CNcomment: ָ��RSA��ԿN��ָ�� */
    hi_u8 *e; /**<  public exponent */     /**< CNcomment: ָ��RSA��ԿE��ָ�� */
    hi_u8 *d; /**<  private exponent */     /**< CNcomment: ָ��RSA˽ԿD��ָ�� */
    hi_u8 *p; /**<  1st prime factor */     /**< CNcomment: ָ��RSA˽ԿP��ָ�� */
    hi_u8 *q; /**<  2nd prime factor */     /**< CNcomment: ָ��RSA˽ԿQ��ָ�� */
    hi_u8 *dp; /**<  D % (P - 1) */    /**< CNcomment: ָ��RSA˽ԿDP��ָ�� */
    hi_u8 *dq; /**<  D % (Q - 1) */    /**< CNcomment: ָ��RSA˽ԿDQ��ָ�� */
    hi_u8 *qp; /**<  1 / (Q % P) */    /**< CNcomment: ָ��RSA˽ԿQP��ָ�� */
    hi_u16 n_len; /**< length of public modulus */  /**< CNcomment: RSA��ԿN�ĳ��� */
    hi_u16 e_len; /**< length of public exponent */  /**< CNcomment: RSA��ԿE�ĳ��� */
    hi_u16 d_len; /**< length of private exponent */  /**< CNcomment: RSA˽ԿD�ĳ��� */
    /**< length of 1st prime factor,should be half of n_len */
    hi_u16 p_len;   /**< CNcomment: RSA˽ԿP�ĳ��ȣ�����Ϊn_len���ȵ�1/2 */
    /**< length of 2nd prime factor,should be half of n_len */
    hi_u16 q_len;   /**< CNcomment: RSA˽ԿQ�ĳ��ȣ�����Ϊn_len���ȵ�1/2 */
    /**< length of D % (P - 1),should be half of n_len */
    hi_u16 dp_len;  /**< CNcomment: RSA˽ԿDP�ĳ��ȣ�����Ϊn_len���ȵ�1/2 */
    /**< length of D % (Q - 1),should be half of n_len */
    hi_u16 dq_len;  /**< CNcomment: RSA˽ԿDQ�ĳ��ȣ�����Ϊn_len���ȵ�1/2 */
    /**< length of 1 / (Q % P),should be half of n_len */
    hi_u16 qp_len;  /**< CNcomment: RSA˽ԿQP�ĳ��ȣ�����Ϊn_len���ȵ�1/2 */
} hi_tee_cipher_rsa_priv_key;

/** RSA public key encryption struct input */
/** CNcomment:RSA ��Կ�ӽ����㷨�����ṹ�� */
typedef struct {
    hi_tee_cipher_rsa_enc_scheme enc_scheme; /** RSA encryption scheme */ /** CNcomment:RSA���ݼӽ����㷨���� */
    hi_tee_cipher_rsa_pub_key pub_key; /** RSA private key struct */       /** CNcomment:RSA˽Կ�ṹ�� */
} hi_tee_cipher_rsa_pub_enc_param;

/** RSA private key decryption struct input */
/** CNcomment:RSA ˽Կ�����㷨�����ṹ�� */
typedef struct {
    hi_tee_cipher_rsa_enc_scheme enc_scheme; /** RSA encryption scheme */ /** CNcomment:RSA���ݼӽ����㷨 */
    hi_tee_cipher_rsa_priv_key priv_key; /** RSA private key struct */   /** CNcomment:RSA˽Կ�ṹ�� */
} hi_tee_cipher_rsa_pri_enc_param;

/** RSA signature struct input */
/** CNcomment:RSAǩ���㷨�����ṹ�� */
typedef struct {
    hi_tee_cipher_rsa_sign_scheme sign_scheme; /** RSA signature scheme */ /** CNcomment:RSA����ǩ������ */
    hi_tee_cipher_rsa_priv_key priv_key; /** RSA private key struct */    /** CNcomment:RSA˽Կ�ṹ�� */
} hi_tee_cipher_rsa_sign_param;

/** RSA signature verify struct input */
/** CNcomment:RSAǩ����֤�㷨��������ṹ�� */
typedef struct {
    hi_tee_cipher_rsa_sign_scheme sign_scheme; /** RSA signature scheme */ /** CNcomment:RSA����ǩ������ */
    hi_tee_cipher_rsa_pub_key pub_key; /** RSA public key struct */        /** CNcomment:RSA��Կ�ṹ�� */
} hi_tee_cipher_rsa_verify_param;

/** rsa sign and verify data struct information */
/** CNcomment: rsaǩ��У������ṹ�� */
typedef struct {
    /** input context to be signature verification. */
    hi_u8 *input;       /** CNcomment:��ǩ����֤�����ݣ����hash_data��Ϊ�գ���ø�ָ�����Ϊ�� */
    hi_u32 input_len;  /** length of input context to be signature. */ /** CNcomment:��ǩ����֤�����ݳ��� */
    /** hash value of context,if NULL, let hash_data = Hash(context) automatically,its length depends on hash type,
     * it is 20 for sha1,28 for sha224,32 for sha256 or sm3,48 for sha384,64 for sha512. */
    hi_u8 *hash_data; /** CNcomment:��ǩ���ı���HASHժҪ��sha1Ϊ20��sha224Ϊ28��sha256Ϊ32��sha384Ϊ48��sha512Ϊ64�����Ϊ�գ����Զ������ı���HASHժҪ */
    /** message of signature, its buffer length must not less than the width of RSA Key N. */
    hi_u8 *sign;       /** CNcomment:ǩ����Ϣ, ���Ļ�������С����С��RSA��ԿN��λ�� */
    hi_u32 *sign_len;  /** length of message of signature buffer. */ /** CNcomment:ǩ����Ϣ�����ݳ��� */
} hi_tee_cipher_rsa_sign_verify_data;

/** SM2 signature struct input */
/** CNcomment: SM2ǩ���㷨�����ṹ�� */
typedef struct {
    hi_u32 d[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 px[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 py[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u8 *id;
    hi_u16 id_len;
} hi_tee_cipher_sm2_sign_param;

/** SM2 signature verify struct input */
/** CNcomment: SM2ǩ����֤�㷨��������ṹ�� */
typedef struct {
    hi_u32 px[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 py[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u8 *id;
    hi_u16 id_len;
} hi_tee_cipher_sm2_verify_param;

/** sm2 sign and verify data struct information */
/** CNcomment: sm2ǩ��У������ṹ�� */
typedef struct {
    /** input context to be signature��maybe null. */
    hi_u8 *msg;       /** CNcomment:��ǩ��������, ���pu8HashData��Ϊ�գ����ָ�����Ϊ�� */
    hi_u32 msg_len;  /** length of input context to be signature. */ /** CNcomment:��ǩ�������ݳ��� */
    hi_u8 *sign_r;    /** The R value of the signature result,its length is 32. */ /** CNcomment:ǩ�������Rֵ������32 */
    hi_u8 *sign_s;    /** The S value of the signature result,its length is 32. */ /** CNcomment:ǩ�������Sֵ������32 */
    hi_u32 sign_buf_len;  /** the length of the signature result,its length is 32. */ /** CNcomment:ǩ��������� */
} hi_tee_cipher_sm2_sign_verify_data;

/** SM2 publuc key encryption struct input */
/** CNcomment: SM2��Կ�����㷨�����ṹ�� */
typedef struct {
    hi_u32 px[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 py[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
} hi_tee_cipher_sm2_enc_param;

/** SM2 private key decryption struct input */
/** CNcomment: SM2˽Կ�����㷨�����ṹ�� */
typedef struct {
    hi_u32 d[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
} hi_tee_cipher_sm2_dec_param;

/** SM2 key generate struct input */
/** CNcomment: SM2��Կ�����㷨�����ṹ�� */
typedef struct {
    hi_u32 d[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 px[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
    hi_u32 py[HI_TEE_CIPHER_SM2_LEN_IN_WORD];
} hi_tee_cipher_sm2_key;

/** CENC subsample expansion struct input */
/** CNcomment: CENC subsample ������չ�ṹ�� */
typedef struct {
    hi_u32 clear_header_len; /* !< the length of clear header */            /**< CNcomment: ͸��ͷ������ */
    hi_u32 pay_load_len; /* !< the length of payload */                /**< CNcomment: ��Ч����ĳ��� */
    /* !< the length of encrypt data in each pattern that should be a multiple of 16 */
    hi_u32 payload_pattern_encrypt_len;  /**< CNcomment: ����pattern�����ĵĳ��ȣ�������16�������� */
    /* !< the length of clear data in each pattern that should be a multiple of 16 */
    hi_u32 payload_pattern_clear_len;    /**< CNcomment: ����pattern�����ĵĳ��ȣ�������16�������� */
    /* !< the offset of first pattern that should be a multiple of 16 */
    hi_u32 payload_pattern_offset_len;   /**< CNcomment: �׸�pattern�е�����ƫ������������16�������� */
    /**< initial vector change flag, 0-don't set, 1-set IV for first package */
    hi_u32 iv_change;                    /**< CNcomment:��ʼ�������, 0-�����ã�1-���õ�һ���� */
    hi_u32 iv[HI_TEE_CIPHER_AES_IV_LEN_IN_WORD]; /**< initial vector */      /**< CNcomment: ��ʼ���� */
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
/** CNcomment: cenc���ܲ����ṹ�� */
typedef struct {
    hi_mem_handle src_buf;;                   /** Physical address of the source data. */ /** CNcomment:Դ���ݵ�ַ��� */
    hi_mem_handle dest_buf;                  /** Physical address of the target data. */ /** CNcomment:Ŀ�����ݵ�ַ��� */
    hi_u32 byte_length;                      /** Length of the decrypted data. */ /** CNcomment:�������ݳ��� */
    hi_tee_cipher_done_callback *symc_done; /** Callback struct, When this structure pointer is not empty, the interface
    will immediately return and call the callback function to notify the user when the calculation is complete,
    but if the structure is empty, the interface will block until the calculation is complete.. */
    /** CNcomment:�������ʱ�Ļص������ṹ�壬���ýṹ��ָ��ǿ�ʱ���ýӿڻ��������ز��ڼ������ʱ���ô˻ص�����֪ͨ�û���
    ������ýṹ��Ϊ�գ���ýӿڻ�����ֱ���������Ϊֹ */
} hi_tee_cenc_decrypt_data;

/** dh gen key data struct information */
/** CNcomment: ����dh key�����ṹ�� */
typedef struct {
    /** Buffer containing the DH generator g used for the operation. The caller ensures it ispadded with leading
     * zeros if the effective size of this key is smaller than the key_size. */
    hi_u8 *g;          /** CNcomment:DH��g���������Ȳ���Key�Ĵ�С��ǰ�油0 */
    /** Buffer containing the DH generator p used for the operation. The caller ensures it is padded with leading
     * zeros if the effective size of this key is smaller than the key_size. */
    hi_u8 *p;          /** CNcomment:DH��p���������Ȳ���Key�Ĵ�С��ǰ�油0 */
    /** Buffer containing an optional input private key from which the public has to be generated.  The caller
     * ensures it is padded with leading zeros if the effective size of this key is smaller than the u32KeySize.
     * If no private key is provided as input (\c input_priv_key=NULL), function generates a random private key
     * and stores it in pu8OutputPrivKey this buffer. */
    hi_u8 *input_priv_key;    /** CNcomment:DH��˽Կ�����Ȳ���Key�Ĵ�С��ǰ�油0, ���Ϊ��ָ�룬�ú���������һ��˽Կ�ŵ�output_priv_key�� */
    /** Buffer where to write the generated private key, in case no private key is providedas input
     * (input_priv_key==NULL). It must be padded with leading zeros if the effective size of the private
     * key is smaller than the buffer size. */
    hi_u8 *output_priv_key;  /** CNcomment:DH��˽Կ�����Ȳ���Key�Ĵ�С��ǰ�油0, ���input_priv_keyΪ��ָ�룬�ú���������һ��˽Կ�ŵ����buffer�� */
    hi_u8 *pub_key;   /** public key. */ /** CNcomment:DH�Ĺ�Կ�����Ȳ���Key�Ĵ�С��ǰ�油0 */
    hi_u32 key_size;  /** DH key size. */ /** CNcomment:DH��Կ���� */
} hi_tee_cipher_dh_gen_key_data;

/** @} */ /** <!-- ==== structure definition end ==== */

/* API declaration */
/** \addtogroup      CIPHER */
/** @{ */ /** <!-- [CIPHER] */
/* ---CIPHER--- */
/**
\brief  init the cipher device.  CNcomment:��ʼ��CIPHER�豸�� CNend
\attention \n
this API is used to start the cipher device.
CNcomment:���ô˽ӿڳ�ʼ��CIPHER�豸�� CNend
\param N/A                                                                      CNcomment:�� CNend
\retval ::HI_SUCCESS  call this API successful.                                 CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE  call this API fails.                                      CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_FAILED_INIT  the cipher device fails to be initialized. CNcomment:CIPHER�豸��ʼ��ʧ�� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_init(hi_void);

/**
\brief  deinit the cipher device.
CNcomment:\brief  ȥ��ʼ��CIPHER�豸�� CNend
\attention \n
this API is used to stop the cipher device. if this API is called repeatedly, HI_SUCCESS is returned,
but only the first operation takes effect.
CNcomment:���ô˽ӿڹر�CIPHER�豸���ظ��رշ��سɹ�����һ�������á� CNend
\param N/A                                                                      CNcomment:�� CNend
\retval ::HI_SUCCESS  call this API successful.                                 CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE  call this API fails.                                      CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.         CNcomment:CIPHER�豸δ��ʼ�� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_deinit(hi_void);

/**
\brief obtain a cipher handle for encryption and decryption.
CNcomment������һ·cipher����� CNend
\param[in] cipher attributes                                                    CNcomment:cipher ���ԡ� CNend
\param[out] cipher cipher handle                                              CNcomment:CIPHER����� CNend
\retval ::HI_SUCCESS call this API successful.                                  CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE call this API fails.                                       CNcomment: APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.         CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  the pointer is null.                     CNcomment:ָ�����Ϊ�� CNend
\retval ::HI_ERR_CIPHER_FAILED_GETHANDLE  the cipher handle fails to be obtained, because there are no available
cipher handles. CNcomment: ��ȡCIPHER���ʧ�ܣ�û�п��е�CIPHER��� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_create(hi_handle *cipher, const hi_tee_cipher_attr *cipher_attr);

/**
\brief destroy the existing cipher handle. CNcomment:�����Ѵ��ڵ�CIPHER����� CNend
\attention \n
this API is used to destroy existing cipher handles.
CNcomment:���ô˽ӿ������Ѿ�������CIPHER����� CNend
\param[in] cipher cipher handle                                                CNcomment:CIPHER����� CNend
\retval ::HI_SUCCESS  call this API successful.                                 CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE  call this API fails.                                      CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.         CNcomment:CIPHER�豸δ��ʼ�� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_destroy(hi_handle cipher);

/**
\brief configures the cipher control information.
CNcomment:\brief ����CIPHER������Ϣ�� CNend
\attention \n
before encryption or decryption, you must call this API to configure the cipher control information.
the first 64-bit data and the last 64-bit data should not be the same when using TDES algorithm.
support AES/DES/3DES/SM1/SM4 algorithm, support ECB/CBC/CTR/OFB/CFB/CCM/GCM mode.
CNcomment:���м��ܽ���ǰ������ʹ�ô˽ӿ�����CIPHER�Ŀ�����Ϣ��
ʹ��TDES�㷨ʱ��������Կ��ǰ��64 bit���ݲ�����ͬ��
֧�� AES/DES/3DES/SM1/SM4 �㷨, ECB/CBC/CTR/OFB/CFB/CCM/GCM ģʽ.CNend
\param[in] cipher cipher handle.                                                CNcomment:CIPHER��� CNend
\param[in] cipher_config cipher control information.                            CNcomment:CIPHER������Ϣ CNend
\retval ::HI_SUCCESS call this API succussful.                                  CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE call this API fails.                                       CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.         CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  the pointer is null.                     CNcomment:ָ�����Ϊ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  the parameter is invalid.                 CNcomment:�������� CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  the handle is invalid.                  CNcomment:����Ƿ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_set_config(hi_handle cipher, const hi_tee_cipher_config *cipher_config);

/**
\brief Get the cipher control information.
CNcomment:\brief ��ȡCIPHER������Ϣ�� CNend
\param[in] cipher Cipher handle.                                                CNcomment:CIPHER��� CNend
\param[in] cipher_config Cipher control information.                            CNcomment:CIPHER������Ϣ CNend
\retval ::HI_SUCCESS Call this API successful.                                  CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Call this API fails.                                       CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.         CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  The pointer is null.                     CNcomment:ָ�����Ϊ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  The parameter is invalid.                 CNcomment:�������� CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  The handle is invalid.                  CNcomment:����Ƿ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_cipher_get_config(hi_handle cipher, const hi_tee_cipher_config *cipher_config);


/**
\brief Get a keyslot handle which banding to cipher handle.
CNcomment����ȡ�󶨵�Cipher�����KeySlot����� CNend

\param[in]  cipher cipher handle                                                CNcomment:CIPHER����� CNend
\param[out] keyslot KeySlot handle                                              CNcomment:KeySlot����� CNend
\retval ::HI_SUCCESS Call this API successful.                                  CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Call this API fails.                                       CNcomment: APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.         CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  The pointer is null.                     CNcomment:ָ�����Ϊ�� CNend
\retval ::HI_ERR_CIPHER_FAILED_GETHANDLE  The keyslot handle fails to be obtained. CNcomment: ��ȡKeySlot���ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_cipher_get_keyslot_handle(hi_handle cipher, hi_handle *keyslot);

/**
\brief Attach a keyslot handle  to cipher handle.
CNcomment����Cipher�����KeySlot����� CNend
\param[in]  cipher cipher handle                                                CNcomment:CIPHER����� CNend
\param[out] keyslot KeySlot handle                                              CNcomment:KeySlot����� CNend
\retval ::HI_SUCCESS Call this API successful.                                  CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Call this API fails.                                       CNcomment: APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.         CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  The pointer is null.                     CNcomment:ָ�����Ϊ�� CNend
\retval ::HI_ERR_CIPHER_FAILED_GETHANDLE  The keyslot handle fails to be obtained. CNcomment: ��ȡKeySlot���ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_cipher_attach_keyslot(hi_handle cipher, hi_handle keyslot);

/**
\brief Detach a keyslot handle from cipher handle.
CNcomment�����Cipher�����KeySlot����󶨡� CNend
\param[in]  cipher cipher handle                                                CNcomment:CIPHER����� CNend
\param[out] keyslot KeySlot handle                                              CNcomment:KeySlot����� CNend
\retval ::HI_SUCCESS Call this API successful.                                  CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Call this API fails.                                       CNcomment: APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.         CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_POINT  The pointer is null.                     CNcomment:ָ�����Ϊ�� CNend
\retval ::HI_ERR_CIPHER_FAILED_GETHANDLE  The keyslot handle fails to be obtained. CNcomment: ��ȡKeySlot���ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_cipher_detach_keyslot(hi_handle cipher,  hi_handle keyslot);

/**
\brief performs encryption.
CNcomment:\brief ���м��ܡ� CNend

\attention \n
this API is used to perform encryption by using the cipher module.
the length of the encrypted data should be a multiple of 8 in TDES mode and 16 in AES mode.
after this operation,the result will affect next operation.if you want to remove vector,
you need to config IV(config ctrl->change_flags.bit1_iv with 1) by transfering hi_tee_cipher_set_config.
CNcomment:ʹ��CIPHER���м��ܲ�����TDESģʽ�¼��ܵ����ݳ���Ӧ����8�ı�����AES��Ӧ����16�ı��������β�����ɺ󣬴˴β�������������������������һ�β�����
���Ҫ�����������Ҫ���´μ��ܲ���֮ǰ����hi_tee_cipher_config_handle��������IV(��Ҫ����ctrl->change_flags.bit1_ivΪ1)�� CNend
\param[in] cipher cipher handle                                                CNcomment:CIPHER��� CNend
\param[in] src_buf buffer handle of the source data                    CNcomment:Դ���ݵ�ַ��� CNend
\param[in] dest_buf buffer handle address of the target data                      CNcomment:Ŀ�����ݵ�ַ��� CNend
\param[in] byte_length   Length of the encrypted data                          CNcomment:�������ݳ��� CNend
\param[in] data_dir data                                                       CNcomment:���ݴ��䷽�� CNend
retval ::HI_SUCCESS   call this API successful.                                CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE   call this API fails.                                    CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.        CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  the parameter is invalid.                CNcomment:�������� CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  the handle is invalid.                 CNcomment:����Ƿ� CNend
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
CNcomment:\brief ���н��� CNend
\attention \n
This API is used to perform decryption by using the cipher module.
The length of the decrypted data should be a multiple of 8 in TDES mode and 16 in AES mode. Besides, the length can
not be bigger than 0xFFFFF.After this operation, the result will affect next operation.If you want to remove vector,
you need to config IV(config pstCtrl->stChangeFlags.bit1IV with 1) by transfering HI_UNF_CIPHER_ConfigHandle.
CNcomment:ʹ��CIPHER���н��ܲ�����TDESģʽ�½��ܵ����ݳ���Ӧ����8�ı�����AES��Ӧ����16�ı��������⣬�������ݳ��Ȳ��ܳ���0xFFFFF��
���β�����ɺ󣬴˴β�������������������������һ�β��������Ҫ�����������Ҫ���´ν��ܲ���֮ǰ����HI_UNF_CIPHER_ConfigHandle
��������IV(��Ҫ����pstCtrl->stChangeFlags.bit1IVΪ1)�� CNend
\param[in] cipher Cipher handle.                                               CNcomment:CIPHER��� CNend
\param[in] src_buf buffer handle of the source data.                   CNcomment:Դ���ݵ�ַ��� CNend
\param[in] dest_buf buffer handle of the target data.                     CNcomment:Ŀ�����ݵ�ַ��� CNend
\param[in] byte_length Length of the decrypted data                            CNcomment:�������ݳ��� CNend
\param[in] data_dir data  direction                                            CNcomment:���ݴ��䷽�� CNend
\retval ::HI_SUCCESS Call this API successful.                                 CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Call this API fails.                                      CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.        CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  The parameter is invalid.                CNcomment:�������� CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  The handle is invalid.                 CNcomment:����Ƿ� CNend
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
CNcomment:\brief ���ж�������ݵļ��ܡ� CNend
\attention \n
You can not encrypt more than 128 data package one time. When HI_ERR_CIPHER_BUSY return, the data package you send
will not be deal, the custmer should decrease the number of data package or run cipher again.Note:When encrypting
more than one packaged data, every one package will be calculated using initial vector configured by
HI_UNF_CIPHER_ConfigHandle.Previous result will not affect the later result.
CNcomment:ÿ�μ��ܵ����ݰ�������಻�ܳ���128��������HI_ERR_CIPHER_BUSY��ʱ���������ݰ�һ��Ҳ���ᱻ�����û���Ҫ������������ݰ������������ٴγ��Լ��ܡ�
ע��: ���ڶ�����Ĳ�����ÿ������ʹ��HI_UNF_CIPHER_ConfigHandle���õ������������㣬ǰһ����������������������������һ���������㣬ÿ�������Ƕ�������ġ�
ǰһ�κ������õĽ��Ҳ����Ӱ���һ�κ������õ��������� CNend
\param[in] cipher cipher handle                                                CNcomment:CIPHER����� CNend
\param[in] data_pkg data package ready for cipher                              CNcomment:�����ܵ����ݰ��� CNend
\param[in] data_pkg_num  number of package ready for cipher                    CNcomment:�����ܵ����ݰ������� CNend
\param[in] data_dir data  direction                                            CNcomment:���ݴ��䷽�� CNend
\retval ::HI_SUCCESS  Call this API successful.                                CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE  Call this API fails.                                     CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  cipher device have not been initialized      CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  parameter error                          CNcomment:�������� CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  handle invalid                         CNcomment:����Ƿ� CNend
\retval ::HI_ERR_CIPHER_BUSY  hardware is busy, it can not deal with all data package once time
CNcomment:Ӳ����æ���޷�һ���Դ���ȫ�������ݰ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_encrypt_multi(hi_handle cipher,
                                   const hi_tee_cipher_data *data_pkg,
                                   hi_u32 data_pkg_num,
                                   hi_tee_cipher_data_dir data_dir);

/**
\brief decrypt multiple packaged data.
CNcomment:\brief ���ж�������ݵĽ��ܡ� CNend
\attention \n
You can not decrypt more than 128 data package one time.When HI_ERR_CIPHER_BUSY return, the data package you send
will not be deal, the custmer should decrease the number of data package or run cipher again.Note:When decrypting
more than one packaged data, every one package will be calculated using initial vector configured by
HI_UNF_CIPHER_ConfigHandle.Previous result will not affect the later result.
CNcomment:ÿ�ν��ܵ����ݰ�������಻�ܳ���128��������HI_ERR_CIPHER_BUSY��ʱ���������ݰ�һ��Ҳ���ᱻ�����û���Ҫ������������ݰ������������ٴγ��Խ��ܡ�
ע��: ���ڶ�����Ĳ�����ÿ������ʹ��HI_UNF_CIPHER_ConfigHandle���õ������������㣬ǰһ����������������������������һ���������㣬ÿ�������Ƕ�������ģ�
ǰһ�κ������õĽ��Ҳ����Ӱ���һ�κ������õ��������� CNend
\param[in] cipher cipher handle                                               CNcomment:CIPHER����� CNend
\param[in] data_pkg data package ready for cipher                             CNcomment:�����ܵ����ݰ��� CNend
\param[in] data_pkg_num  number of package ready for cipher                   CNcomment:�����ܵ����ݰ������� CNend
\param[in] data_dir data  direction                                           CNcomment:���ݴ��䷽�� CNend
\retval ::HI_SUCCESS  Call this API succussful.                               CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE  Call this API fails.                                    CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  cipher device have not been initialized     CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  parameter error                         CNcomment:�������� CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  handle invalid                        CNcomment:����Ƿ� CNend
\retval ::HI_ERR_CIPHER_BUSY  hardware is busy, it can not deal with all data package once time
CNcomment:Ӳ����æ���޷�һ���Դ���ȫ�������ݰ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_decrypt_multi(hi_handle cipher,
                                   const hi_tee_cipher_data *data_pkg,
                                   hi_u32 data_pkg_num,
                                   hi_tee_cipher_data_dir data_dir);

/**
\brief CENC decryption a ciphertext.
CNcomment: CENC��ʽ����һ�����ġ� CNend
\attention \n
this API is used to perform decryption ciphertext base on CENC format.
CNcomment:ʹ��CIPHER����CENC��ʽ���ܲ����� CNend
\param[in] cipher cipher handle                                                   CNcomment:CIPHER��� CNend
\param[in] cenc key for cipher decryption,its length should be 16.                CNcomment:CIPHER ������Կ,����Ϊ16. CNend
\param[in] in_phy_addr physical address of the source data                        CNcomment:Դ���������ַ CNend
\param[in] out_phy_addr physical address of the target data                       CNcomment:Ŀ�����������ַ CNend
\param[in] byte_length   Length of the decrypted data                             CNcomment:�������ݳ��� CNend
\param[in] symc_done callback struct, when this structure pointer is not empty, the interface will immediately
           return and call the callback function to notify the user when the calculation is complete,
           but if the structure is empty, the interface will block until the calculation is complete.
           CNcomment:�������ʱ�Ļص������ṹ�壬���ýṹ��ָ��ǿ�ʱ���ýӿڻ��������ز��ڼ������ʱ
           ���ô˻ص�����֪ͨ�û���������ýṹ��Ϊ�գ���ýӿڻ�����ֱ���������Ϊֹ CNend
\retval ::HI_SUCCESS  call this API succussful.                                    CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE  call this API fails.                                         CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  the cipher device is not initialized.            CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  the parameter is invalid.                    CNcomment:�������� CNend
\retval ::HI_ERR_CIPHER_INVALID_HANDLE  the handle is invalid.                     CNcomment:����Ƿ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_cenc_decrypt(hi_handle cipher, const hi_tee_cipher_cenc_param *param,
                                  hi_tee_cenc_decrypt_data *cenc_decrypt_data);

/**
\brief get the tag data of CCM/GCM.
CNcomment:\brief ��ȡCCM/GCM��TAG���ݡ� CNend
\attention \n
This API is used to get the tag data of CCM/GCM.
\param[in] cipher cipher handle                                                 CNcomment:CIPHER����� CNend
\param[out] tag tag data of CCM/GCM                                             CNcomment:TAGָ�� CNend
\param[in/out] tag_len tag data length of CCM/GCM, the input should be 16 now.  CNcomment:TAG���ݳ��ȣ�����������Ϊ16 CNend
\retval ::HI_SUCCESS  Call this API succussful.                                 CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE  Call this API fails.                                      CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CIPHER_NOT_INIT  The cipher device is not initialized.         CNcomment:CIPHER�豸δ��ʼ�� CNend
\retval ::HI_ERR_CIPHER_INVALID_PARA  The parameter is invalid.                 CNcomment:�������� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_get_tag(hi_handle cipher, hi_u8 *tag, hi_u32 *tag_len);

/**
\brief get a word of random number.
CNcomment:\brief ��ȡһ���ֵ�������� CNend
\attention \n
this API is used to obtain the random number from the hardware.
CNcomment: ���ô˽ӿ����ڻ�ȡ������� CNend
\param[out] random_number point to the random number.                      CNcomment:�������ֵ�� CNend
\retval ::HI_SUCCESS  call this API successful.                            CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                                 CNcomment: APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_get_random_number(hi_u32 *random_number);

/**
\brief get the random bytes.
CNcomment:\brief ��ȡ������� CNend
\attention \n
this API is used to obtain the random number from the hardware.
CNcomment:���ô˽ӿ����ڻ�ȡ������� CNend
\param[out] random_number point to the random number.                      CNcomment:�������ֵ�� CNend
\param[in]  bytes size of the random bytes.                                CNcomment:�������С�� CNend
\retval ::HI_SUCCESS  call this API successful.                            CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                                 CNcomment: APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_get_multi_random_bytes(hi_u32 bytes, hi_u8 *random_byte);

/**
\brief init the hash module, if other program is using the hash module, the API will return failure.
CNcomment:\brief ��ʼ��HASHģ�飬�����������������ʹ��HASHģ�飬����ʧ��״̬�� CNend
\attention \n
N/A
\param[in] attr: the hash calculating structure input.                      CNcomment:���ڼ���hash�Ľṹ����� CNend
\param[out] hash: the output hash handle.                                   CNcomment:�����hash��� CNend
\retval ::HI_SUCCESS  call this API successful.                             CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                                  CNcomment: APIϵͳ����ʧ�� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_hash_init(hi_tee_cipher_hash_attr *hash_attr, hi_handle *hash);

/**
\brief calculate the hash, if the size of the data to be calculated is very big and the DDR ram is not enough,
this API can calculate the data one block by one block. attention: the input block length must be 64bytes
aligned except for the last block.
CNcomment:\brief ����hashֵ�������Ҫ������������Ƚϴ󣬸ýӿڿ���ʵ��һ��blockһ��block�ļ��㣬�����������Ƚϴ������£��ڴ治������⡣
�ر�ע�⣬�������һ��block��ǰ���ÿһ������ĳ��ȶ�������64�ֽڶ��롣CNend
\attention \n
N/A
\param[in] hashandl:  hash handle.                                        CNcomment:hash����� CNend
\param[in] input_data:  the input data buffer.                            CNcomment:�������ݻ��� CNend
\param[in] input_data_len:  the input data length, attention: the block length input
must be 64bytes aligned except the last block!
CNcomment:�������ݵĳ��ȡ���Ҫ�� �������ݿ�ĳ��ȱ�����64�ֽڶ��룬���һ��block�޴����ơ� CNend
\retval ::HI_SUCCESS  call this API successful.                           CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                                CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_hash_update(hi_handle hash, const hi_u8 *input_data, hi_u32 input_data_len);

/**
\brief get the final hash value, after calculate all of the data, call this API to get the final hash value and close
the handle.if there is some reason need to interrupt the calculation, this API should also be call to close the handle.
CNcomment:��ȡhashֵ���ڼ��������е����ݺ󣬵�������ӿڻ�ȡ���յ�hashֵ���ýӿ�ͬʱ��ر�hash���������ڼ�������У���Ҫ�жϼ��㣬Ҳ������øýӿڹر�hash����� CNend
\attention \n
N/A
\param[in] hash:  hash handle.                                          CNcomment:hash�����  CNend
\param[out] output_hash:  the final output hash value��and its length depends on hash type,
it is 20 for sha1,28 for sha224,32 for sha256 or sm3,48 for sha384,64 for sha512.
\param[in/out] hash_len:  The final output buffer lengrh.
CNcomment:�����hashֵ��������hash���;�����sha1ʱ�������20��sha224�������28��sha256����sm3�������32��sha384�������48��sha512�������64�� CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_hash_final(hi_handle hash, hi_u8 *hash_buf, hi_u32 *hash_len);

/**
\brief RSA encryption a plaintext with a RSA public key.
CNcomment:ʹ��RSA��Կ����һ�����ġ� CNend
\attention \n
N/A
\param[in] param:   encryption struct.                                  CNcomment:�������Խṹ�塣 CNend
\param[in] input��   input data to be encryption                        CNcomment: �����ܵ����ݡ� CNend
\param[out] input_len:   length of input data to be encryption          CNcomment: �����ܵ����ݳ��ȡ� CNend
\param[out] output�� output data to be encryption, its buffer length must not less than the width of RSA key N.
CNcomment: ���ܽ������, ���Ļ�������С����С��RSA��ԿN��λ�� CNend
\param[in/out] output_len: length of output buffer to be                CNcomment: ���ܽ�������ݳ��ȡ� CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_public_encrypt(hi_tee_cipher_rsa_pub_enc_param *param,
                                        hi_u8 *input, hi_u32 input_len,
                                        hi_u8 *output, hi_u32 *output_len);

/**
\brief RSA decryption a ciphertext with a RSA private key.
CNcomment:ʹ��RSA˽Կ����һ�����ġ� CNend
\attention \n
N/A
\param[in] param:   decryption struct.                                  CNcomment: ��Կ�������Խṹ�塣 CNend
\param[in] input��   input data to be decryption                        CNcomment: �����ܵ����ݡ� CNend
\param[out] input_len:   length of input data to be decryption          CNcomment: �����ܵ����ݳ��ȡ� CNend
\param[out] output�� output buffer to storage decryption data, its length must not less than the width of RSA key N.
CNcomment: ���ܽ������, ���Ļ�������С����С��RSA��ԿN��λ�� CNend
\param[in/out] output_len: length of output buffer to be decryption     CNcomment: ���ܽ�������ݳ��ȡ� CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_private_decrypt(hi_tee_cipher_rsa_pri_enc_param *param,
                                         hi_u8 *input, hi_u32 input_len,
                                         hi_u8 *output, hi_u32 *output_len);

/**
\brief RSA encryption a plaintext with a RSA private key.
CNcomment:ʹ��RSA˽Կ����һ�����ġ� CNend
\attention \n
N/A
\param[in] param:   encryption struct.                                  CNcomment:�������Խṹ�塣 CNend
\param[in] input��   input data to be encryption                        CNcomment: �����ܵ����ݡ� CNend
\param[out] input_len:   length of input data to be encryption          CNcomment: �����ܵ����ݳ��ȡ� CNend
\param[out] output�� output data to be encryption, its buffer length must not less than the width of RSA key N.
CNcomment: ���ܽ������, ���Ļ�������С����С��RSA��ԿN��λ�� CNend
\param[in/out] output_len: length of output buffer to be encryption     CNcomment: ���ܽ�������ݳ��ȡ� CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_private_encrypt(hi_tee_cipher_rsa_pri_enc_param *param,
                                         hi_u8 *input, hi_u32 input_len,
                                         hi_u8 *output, hi_u32 *output_len);

/**
\brief RSA decryption a ciphertext with a RSA public key.
CNcomment:ʹ��RSA��Կ����һ�����ġ� CNend
\attention \n
N/A
\param[in] rsa_verify:   decryption struct.                               CNcomment: �������Խṹ�塣 CNend
\param[in] input��   input data to be decryption                          CNcomment: �����ܵ����ݡ� CNend
\param[out] input_len:   length of input data to be decryption            CNcomment: �����ܵ����ݳ��ȡ� CNend
\param[out] output�� output buffer to storage decryption data, its length must not less than the width of RSA key N
CNcomment: ���ܽ������, ���Ļ�������С����С��RSA��ԿN��λ�� CNend
\param[in/out] output_len: length of output buffer to be decryption     CNcomment: ���ܽ�������ݳ��ȡ� CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_public_decrypt(hi_tee_cipher_rsa_pub_enc_param *param,
                                        hi_u8 *input, hi_u32 input_len,
                                        hi_u8 *output, hi_u32 *output_len);

/**
\brief RSA signature a context with appendix, where a signer��s RSA private key is used.
CNcomment:ʹ��RSA˽Կǩ��һ���ı��� CNend
\attention \n
N/A
\param[in] param:      signature struct.                                CNcomment: ǩ�����Խṹ�塣 CNend
\param[in] input��       input context to be signature��maybe null
CNcomment: ��ǩ��������, ���hasdata��Ϊ�գ����ָ�տ���Ϊ�ա� CNend
\param[in] input_len:        length of input context to be signature
CNcomment: ��ǩ�������ݳ��ȡ� CNend
\param[in] hash_data��    hash value of context,if NULL, let hasdata = hash(context) automatically,its length
depends on hash type, it is 20 for sha1,28 for sha224,32 for sha256 or sm3,48 for sha384,64 for sha512.
ncomment: ��ǩ���ı���HASHժҪ��
CNcomment:�����hashժҪ��������hash���;�����sha1ʱ�������20��sha224�������28��sha256�������32��sha384�������48��
sha512�������64�����Ϊ�գ����Զ������ı���HASHժҪ�� CNend
\param[out] out_sign��    output message of signature, its buffer length must not less than the width of RSA key N.
CNcomment: ǩ����Ϣ, ���Ļ�������С����С��RSA��ԿN��λ�� CNend
\param[in/out] out_sign_len: length of message of signature buffer      CNcomment: ǩ����Ϣ�����ݳ��ȡ� CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_sign(hi_tee_cipher_rsa_sign_param *param, hi_tee_cipher_rsa_sign_verify_data *rsa_sign_data);

/**
\brief RSA signature verification a context with appendix, where a signer��s RSA public key is used.
CNcomment:ʹ��RSA��Կǩ����֤һ���ı��� CNend
\attention \n
N/A
\param[in] rsa_verify:    signature verification struct.                CNcomment: ǩ����֤���Խṹ�塣 CNend
\param[in] input��       input context to be signature verification��maybe null
CNcomment: ��ǩ����֤������, ���hasdata��Ϊ�գ����ָ�տ���Ϊ�ա� CNend
\param[in] input_len:        length of input context to be signature    CNcomment: ��ǩ����֤�����ݳ��ȡ� CNend
\param[in] hash_data��    hash value of context,if NULL, let hasdata = hash(context) automatically,its length
depends on hash type, it is 20 for sha1,28 for sha224,32 for sha256 or sm3,48 for sha384,64 for sha512.
ncomment: ��ǩ���ı���HASHժҪ��
CNcomment:�����hashժҪ��������hash���;�����sha1ʱ�������20��sha224�������28��sha256�������32��sha384�������48��sha512�������64��
ncomment: ��ǩ���ı���HASHժҪ�����Ϊ�գ����Զ������ı���HASHժҪ�� CNend
\param[in] in_sign��      message of signature, its buffer length must not less than the width of RSA key N.
CNcomment: ǩ����Ϣ, ���Ļ�������С����С��RSA��ԿN��λ�� CNend
\param[in] in_sign_len:   length of message of signature                       CNcomment: ǩ����Ϣ�����ݳ��ȡ� CNend
\retval ::HI_SUCCESS  call this API successful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_rsa_verify(
    hi_tee_cipher_rsa_verify_param *rsa_verify, hi_tee_cipher_rsa_sign_verify_data *rsa_verify_data);

/**
\brief SM2 signature a context with appendix, where a signer��s SM2 private key is used.
CNcomment:ʹ��SM2˽Կǩ��һ���ı��� CNend
\attention \n
N/A
\param[in] sm2_sign:      signature struct.                                    CNcomment: ǩ�����Խṹ�塣 CNend
\param[in/out] sm2_sign_data:  signature data struct                           CNcomment: ǩ����������ݽṹ�塣 CNend
\param[in] sing_buf_len:  length of signature buffer                           CNcomment: ��ǩ�������ݳ��ȡ� CNend
\retval ::HI_SUCCESS  call this API succussful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_sm2_sign(hi_tee_cipher_sm2_sign_param *param, hi_tee_cipher_sm2_sign_verify_data *sm2_sign_data);

/**
\brief SM2 signature verification a context with appendix, where a signer��s SM2 public key is used.
CNcomment:ʹ��SM2��Կǩ����֤һ���ı��� CNend
\attention \n
N/A
\param[in] param:    signature verification struct.                         CNcomment: ǩ����֤���Խṹ�塣 CNend
\param[in/out] sm2_verify_data:  signature data struct                      CNcomment: ǩ����������ݽṹ�塣 CNend
\retval ::HI_SUCCESS  call this API succussful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_sm2_verify(
    hi_tee_cipher_sm2_verify_param *param, const hi_tee_cipher_sm2_sign_verify_data *sm2_verify_data);

/**
\brief SM2 encryption a plaintext with a RSA public key.
CNcomment:ʹ��SM2��Կ����һ�����ġ� CNend
\attention \n
N/A
\param[in] param:   encryption struct.                                  CNcomment: �������Խṹ�塣 CNend
\param[in] msg��     input data to be encryption                        CNcomment: �����ܵ����ݡ� CNend
\param[in] msg_len:   length of input data to be encryption             CNcomment: �����ܵ����ݳ��ȡ� CNend
\param[out] c��      output data to be encryption                       CNcomment: ���ܽ�����ݡ� CNend
\param[in/out] c_len:   length of output buffer to be encryption        CNcomment: ���ܽ�������ݳ��ȡ� CNend
\retval ::HI_SUCCESS  call this API succussful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_sm2_encrypt(hi_tee_cipher_sm2_enc_param *param, hi_u8 *msg, hi_u32 msg_len, hi_u8 *c,
                                 hi_u32 *c_len);

/**
\brief RSA decryption a ciphertext with a SM2 private key.
CNcomment:ʹ��SM2˽Կ����һ�����ġ� CNend
\attention \n
N/A
\param[in] param:   decryption struct.                                   CNcomment: ��Կ�������Խṹ�塣 CNend
\param[in] c��       input data to be decryption                         CNcomment: �����ܵ����ݡ� CNend
\param[out] c_len:    length of input data to be decryption              CNcomment: �����ܵ����ݳ��ȡ� CNend
\param[out] msg��    output data to be decryption                        CNcomment: ���ܽ�����ݡ� CNend
\param[in/out] msg_len: length of output buffer to be decryption         CNcomment: ���ܽ�������ݳ��ȡ� CNend
\retval ::HI_SUCCESS  call this API succussful.                          CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                               CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_sm2_decrypt(hi_tee_cipher_sm2_dec_param *param, hi_u8 *c, hi_u32 c_len, hi_u8 *msg,
                                 hi_u32 *msg_len);

/**
\brief generate a SM2 key pair.
CNcomment:����һ��SM2��Կ�ԡ� CNend
\attention \n
N/A
\param[out] sm2_key:   key pair struct.                                 CNcomment: SM2��Կ�ԡ� CNend
\retval ::HI_SUCCESS  call this API succussful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_sm2_gen_key(hi_tee_cipher_sm2_key *sm2_key);

/**
\brief calculate a key of PBKDF2
CNcomment: ����PBKDF2��Կ CNend
\attention \n
N/A
\param[in] param:  the PBKDF2 key calculating structure input.        CNcomment:PBKDF2��Կ����ṹ�� CNend
\param[out] output:  the final output hash value, its buffer length must not less than param->key_length.
CNcomment:�����PBKDF2��Կ, ���Ļ�������С����С��param->key_length��   CNend
\retval ::HI_SUCCESS  call this API successful.                      CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                           CNcomment:APIϵͳ����ʧ�ܡ� CNend

\see \n
N/A
 */
hi_s32 hi_tee_cipher_pbkdf2(const hi_tee_cipher_pbkdf2_param *param, hi_u8 *output, hi_u32 output_len);

/**
\brief generate diffie-hellman public/private key pair from g and p parameters.
the public key is equal to g^x mod p,where x is random number considered as the private key.
CNcomment: ����DH��˽��Կ�ԡ� CNend
\attention \n
N/A
\param[in/out] param: dh gen key data struct            CNcomment: DH������Կ���ݽṹ��. CNend
\retval ::HI_SUCCESS  call this API succussful.         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
 */
hi_s32 hi_tee_cipher_dh_gen_key(hi_tee_cipher_dh_gen_key_data *param);

/**
\brief compute ECDH shared secret key. this key corresponds to the X coordinates of the computed P point.
CNcomment: ����ECC DH������Կ�� CNend
\attention \n
N/A
\param[in] params:  elliptic curve domain parameters. the caller is in charge padding each buffer with leading zeros
if the effective size of the domain parameter conveyed is smaller than params->key_size.
CNcomment: ECC��Բ���߲��������Ȳ���key�Ĵ�С��ǰ�油0�� CNend
\param[in] priv_key: buffer containing the ECDH private key. the caller ensures it is padded with leading zeros if
the effective size of this key is smaller than the key_size.
CNcomment: ECDH˽Կ�����Ȳ���key�Ĵ�С��ǰ�油0�� CNend
\param[in] other_pub_key: buffer containing the other peer's public key. it is padded by the caller with leading
zeros if the effective size of the public key is smaller than the buffer size.
CNcomment: �Է���ECDH��Կ��X���꣬���Ȳ���key�Ĵ�С��ǰ�油0�� CNend
\param[out] shared_secret:  buffer where to write the computed shared secret. the caller ensures it is padded with
leading zeros if the effective size of this key is smaller than the key_size.
CNcomment: ECDH������Կ�����Ȳ���key�Ĵ�С��ǰ�油0�� CNend
\retval ::HI_SUCCESS  call this API succussful.                         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  call this API fails.                              CNcomment:APIϵͳ����ʧ�ܡ� CNend
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
