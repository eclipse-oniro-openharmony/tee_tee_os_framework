/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Define security-related structures
 * Author: sdk
 * Create: 2019-11-20
 */

#ifndef __HI_TEE_SECURITY_H__
#define __HI_TEE_SECURITY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*************************** Structure Definition ****************************/
/** \addtogroup      Security */
/** @{ */  /** <!-- [Security] */

/**Define the algorithm of crypto engine.*/
typedef enum {
    HI_TEE_CRYPTO_ALG_CSA2 = 0,          /**<CSA2.0*/
    HI_TEE_CRYPTO_ALG_CSA3,              /**<CSA3.0*/
    HI_TEE_CRYPTO_ALG_ASA,               /**<ASA 64/128 Algorithm*/
    HI_TEE_CRYPTO_ALG_ASA_LIGHT,         /**<ASA light Algorithm*/

    HI_TEE_CRYPTO_ALG_AES_ECB_T = 0x10,  /**<SPE AES ECB, the clear stream left in the tail*/
    HI_TEE_CRYPTO_ALG_AES_ECB_L,         /**<AES_ECB_L the clear stream left in the leading*/

    HI_TEE_CRYPTO_ALG_AES_CBC_T,         /**<AES CBC, the clear stream left in the tail*/
    HI_TEE_CRYPTO_ALG_AES_CISSA,         /**<Common IPTV Software-oriented Scrambling Algorithm(CISSA), golbal IV*/
    HI_TEE_CRYPTO_ALG_AES_CBC_L,         /**<AES_CBC_L the clear stream left in the leading*/

    HI_TEE_CRYPTO_ALG_AES_CBC_IDSA,      /**<AES128 CBC Payload, ATIS IIF Default Scrambling Algorithm (IDSA), the difference between AES_CBC_IDSA and AES_IPTV is AES_CBC_IDSA only support 0 IV*/
    HI_TEE_CRYPTO_ALG_AES_IPTV,          /**<AES IPTV of SPE*/
    HI_TEE_CRYPTO_ALG_AES_CTR,           /**<AES CTR*/

    HI_TEE_CRYPTO_ALG_DES_CI = 0x20,     /**<DES CBC*/
    HI_TEE_CRYPTO_ALG_DES_CBC,           /**<DES CBC*/
    HI_TEE_CRYPTO_ALG_DES_CBC_IDSA,      /**<DES CBC Payload, ATIS IIF Default Scrambling Algorithm(IDSA), Not support set IV*/

    HI_TEE_CRYPTO_ALG_SMS4_ECB = 0x30,   /**<SMS4 ECB*/
    HI_TEE_CRYPTO_ALG_SMS4_CBC,          /**<SMS4 CBC*/
    HI_TEE_CRYPTO_ALG_SMS4_CBC_IDSA,     /**<SMS4 CBC Payload, ATIS IIF Default Scrambling Algorithm(IDSA), Not support set IV*/

    HI_TEE_CRYPTO_ALG_TDES_ECB = 0x40,   /**<TDES ECB*/
    HI_TEE_CRYPTO_ALG_TDES_CBC,          /**<TDES CBC*/
    HI_TEE_CRYPTO_ALG_TDES_CBC_IDSA,     /**<TDES CBC Payload, ATIS IIF Default Scrambling Algorithm(IDSA), Not support set IV*/

    HI_TEE_CRYPTO_ALG_MULTI2_ECB = 0x50, /**<MULTI2 ECB*/
    HI_TEE_CRYPTO_ALG_MULTI2_CBC,        /**<MULTI2 CBC*/
    HI_TEE_CRYPTO_ALG_MULTI2_CBC_IDSA,   /**<MULTI2 CBC Payload, ATIS IIF Default Scrambling Algorithm(IDSA), Not support set IV*/

    HI_TEE_CRYPTO_ALG_RAW_AES = 0x4000,
    HI_TEE_CRYPTO_ALG_RAW_DES,
    HI_TEE_CRYPTO_ALG_RAW_SM4,
    HI_TEE_CRYPTO_ALG_RAW_TDES,
    HI_TEE_CRYPTO_ALG_RAW_HMAC_SHA1,
    HI_TEE_CRYPTO_ALG_RAW_HMAC_SHA2,
    HI_TEE_CRYPTO_ALG_RAW_HMAC_SM3,
    HI_TEE_CRYPTO_ALG_RAW_HDCP,

    HI_TEE_CRYPTO_ALG_MAX
} hi_tee_crypto_alg;

/** @} */  /** <!-- ==== Structure Definition End ==== */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __HI_TEE_SECURITY_H__ */
