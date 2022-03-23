/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: declare of rsa api
 * Author     : z00293770
 * Create     : 2018/12/18
 */

#ifndef __ADAPT_RSA_H__
#define __ADAPT_RSA_H__

#include "cc_rsa_kg.h"
#include "cc_rsa_error.h"

/* the RSA public key user validity TAG */
#define CC_RSA_PUB_KEY_VALIDATION_TAG         0x13579BDF

/* the RSA private key user validity TAG */
#define CC_RSA_PRIV_KEY_VALIDATION_TAG        0x2468ACE0

/* the RSA sign Context user validity TAG */
#define CC_RSA_SIGN_CONTEXT_VALIDATION_TAG    0x98765432
#define CC_RSA_VERIFY_CONTEXT_VALIDATION_TAG  0x45678901

#define CC_RSA_KEY_BUFFER_SIZE_IN_BYTE       (WORD2BYTE(CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS))
#define CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE    ((WORD2BYTE(CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS)) / 2)

/*
 * @brief          : EPS_RSAGenKeyPair
 * @param [in/out] : rndContext_ptr  - noused(just adapt for cc seceng).
 * @param [in]     : PubExp_ptr - The pointer to the public exponent (public key)
 * @param [in]     : PubExpSizeInBytes - The public exponent size in bytes.
 * @param [in]     : KeySize  - The size of the key in bits. Supported sizes are 256 bit multiples
 *                   between 512 - 4096;
 * @param [out]    : pCcUserPrivKey - A pointer to the private key structure.
 *                   This structure is used as input to the CC_RsaPrimDecrypt API.
 * @param [out]    : pCcUserPubKey - A pointer to the public key structure.
 *                   This structure is used as input to the CC_RsaPrimEncrypt API.
 * @param [in]     : KeyGenData_ptr -   - noused(just adapt for cc seceng).
 * @param [in]     : pFipsCtx -   - noused(just adapt for cc seceng).
 * @return         : ::CCError_t error code
 *                   CC_OK,
 *                   CC_RSA_INVALID_EXPONENT_POINTER_ERROR,
 *                   CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
 *                   CC_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
 *                   CC_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
 *                   CC_RSA_INVALID_MODULUS_SIZE,
 *                   CC_RSA_INVALID_EXPONENT_SIZE
 * @note           : generates a Pair of public and private keys on non CRT mode
 */
CEXPORT_C CCError_t EPS_RSAGenKeyPair(
	CCRndContext_t           *rndContext_ptr,
	uint8_t                  *PubExp_ptr,
	size_t                    PubExpSizeInBytes,
	size_t                    KeySize,
	CCRsaUserPrivKey_t       *pCcUserPrivKey,
	CCRsaUserPubKey_t        *pCcUserPubKey,
	CCRsaKgData_t            *KeyGenData_ptr,
	CCRsaKgFipsContext_t     *pFipsCtx);

/*
 * @brief          : EPS_RSAGenKeyPairCRT
 * @param [in/out] : rndContext_ptr  - noused(just adapt for cc seceng).
 * @param [in]     : PubExp_ptr - The pointer to the public exponent (public key)
 * @param [in]     : PubExpSizeInBytes - The public exponent size in bytes.
 * @param [in]     : KeySize  - The size of the key in bits. Supported sizes are 256 bit multiples
 *                   between 512 - 4096;
 * @param [out]    : pCcUserPrivKey - A pointer to the private key structure.
 *                   This structure is used as input to the CC_RsaPrimDecrypt API.
 * @param [out]    : pCcUserPubKey - A pointer to the public key structure.
 *                   This structure is used as input to the CC_RsaPrimEncrypt API.
 * @param [in]     : KeyGenData_ptr -   - noused(just adapt for cc seceng).
 * @param [in]     : pFipsCtx -   - noused(just adapt for cc seceng).
 * @return         : ::CCError_t error code
 *                   CC_OK,
 *                   CC_RSA_INVALID_EXPONENT_POINTER_ERROR,
 *                   CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
 *                   CC_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
 *                   CC_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
 *                   CC_RSA_INVALID_MODULUS_SIZE,
 *                   CC_RSA_INVALID_EXPONENT_SIZE
 * @note           : generates a Pair of public and private keys on CRT mode.
 */
CEXPORT_C CCError_t EPS_RSAGenKeyPairCRT(
	CCRndContext_t           *rndContext_ptr,
	uint8_t                  *PubExp_ptr,
	size_t                    PubExpSizeInBytes,
	size_t                    KeySize,
	CCRsaUserPrivKey_t       *pCcUserPrivKey,
	CCRsaUserPubKey_t        *pCcUserPubKey,
	CCRsaKgData_t            *KeyGenData_ptr,
	CCRsaKgFipsContext_t     *pFipsCtx);

/*
 * @brief          : EPS_RSABuildPubKey
 * @param[out]     : PubKey_ptr - a pointer to the public key structure. This structure will be
 *                   used as an input to the CC_RsaPrimEncrypt API.
 * @param[in]      : Exponent_ptr - a pointer to the exponent stream of bytes ( Big endian ).
 * @param[in]      : ExponentSize - The size of the exponent in bytes.
 * @param[in]      : Modulus_ptr  - a pointer to the modulus stream of bytes ( Big endian ) the MS
 *                   bit must be set to '1'.
 * @param[in]      : ModulusSize  - The size of the modulus in bytes. Sizes supported according to
 *                   used platform from 64 to 256 bytes and in some platforms up to 512 bytes.
 * @note           : populates a CCRsaPubKey_t structure with the provided modulus and exponent
 *                   the modulus and the exponent are presented in big endian.
 */
CEXPORT_C CCError_t EPS_RSABuildPubKey(
	CCRsaUserPubKey_t        *UserPubKey_ptr,
	uint8_t                  *Exponent_ptr,
	size_t                    ExponentSize,
	uint8_t                  *Modulus_ptr,
	size_t                    ModulusSize);

/*
 * @brief          : eps_adapt_rsa_build_privkey
 * @param[out]     : UserPrivKey_ptr - a pointer to the public key structure. this structure will be used as
 *                   an input to the CC_RsaPrimDecrypt API.
 * @param[in]      : PrivExponent_ptr - a pointer to the private exponent stream of bytes ( Big endian ).
 * @param[in]      : PrivExponentSize - the size of the private exponent in bytes.
 * @param[in]      : Exponent_ptr - a pointer to the exponent stream of bytes ( Big endian ).
 * @param[in]      : ExponentSize - the size of the exponent in bytes.
 * @param[in]      : Modulus_ptr  - a pointer to the modulus stream of bytes ( Big endian ) the MS
 *                   bit must be set to '1'.
 * @param[in]      : ModulusSize  - the size of the modulus in bytes. Sizes supported according to
 *                   used platform from 64 to 256 bytes and in some platforms up to 512 bytes.
 * @note           : populates a CCRsaPrivKey_t structure with
 *                   the provided modulus and exponent, marking the key as a "non-CRT" key.
 */
CEXPORT_C CCError_t EPS_RSABuildPrivKey(
	CCRsaUserPrivKey_t       *UserPrivKey_ptr,
	uint8_t                  *PrivExponent_ptr,
	size_t                    PrivExponentSize,
	uint8_t                  *PubExponent_ptr,
	size_t                    PubExponentSize,
	uint8_t                  *Modulus_ptr,
	size_t                    ModulusSize);

/*
 * @brief          : eps_adapt_rsa_build_privkeyCRT
 * @param[out]     : UserPrivKey_ptr - A pointer to the public key structure.
 *                   This structure is used as input to the CC_RsaPrimDecrypt API.
 * @param[in]      : P_ptr - A pointer to the first factor stream of bytes (Big-Endian format)
 * @param[in]      : PSize - The size of the first factor, in bytes.
 * @param[in]      : Q_ptr - A pointer to the second factor stream of bytes (Big-Endian format)
 * @param[in]      : QSize - The size of the second factor, in bytes.
 * @param[in]      : dP_ptr - A pointer to the first factor's CRT exponent stream of bytes (Big-Endian format)
 * @param[in]      : dPSize - The size of the first factor's CRT exponent, in bytes.
 * @param[in]      : dQ_ptr - A pointer to the second factor's CRT exponent stream of bytes (Big-Endian format)
 * @param[in]      : dQSize - The size of the second factor's CRT exponent, in bytes.
 * @param[in]      : qInv_ptr - A pointer to the first CRT coefficient stream of bytes (Big-Endian format)
 * @param[in]      : qInvSize - The size of the first CRT coefficient, in bytes.
 * @note           : populates a CCRsaPrivKey_t structure with
 *                   the provided parameters, marking the key as a "CRT" key.
 */
CEXPORT_C CCError_t EPS_RSABuildPrivKeyCRT(
	CCRsaUserPrivKey_t       *UserPrivKey_ptr,
	uint8_t                  *P_ptr,
	size_t                    PSize,
	uint8_t                  *Q_ptr,
	size_t                    QSize,
	uint8_t                  *dP_ptr,
	size_t                    dPSize,
	uint8_t                  *dQ_ptr,
	size_t                    dQSize,
	uint8_t                  *qInv_ptr,
	size_t                    qInvSize);

/*
 * @brief          : eps_adapt_rsa_get_pubkey
 * @param[in]      : UserPubKey_ptr - A pointer to the public key structure.
 *                   This structure is used as input to the CC_RsaPrimEncrypt API.
 * @param[out]     : Exponent_ptr - A pointer to the exponent stream of bytes (Big-Endian format)
 * @param[in,out]  : ExponentSize_ptr - the size of the exponent buffer in bytes, it is updated to the
 *                   actual size of the exponent, in bytes.
 * @param[out]     : Modulus_ptr  - A pointer to the modulus stream of bytes (Big-Endian format).
 *                   The MS (most significant) bit must be set to '1'.
 * @param[in,out]  : ModulusSize_ptr  - the size of the modulus buffer in bytes, it is updated to the
 *                   actual size of the modulus, in bytes.
 * @note           : gets the e,n public key from the database.
 */
CEXPORT_C CCError_t EPS_RSAGetPubKey(
	CCRsaUserPubKey_t        *UserPubKey_ptr,
	uint8_t                  *Exponent_ptr,
	uint16_t                 *ExponentSize_ptr,
	uint8_t                  *Modulus_ptr,
	uint16_t                 *ModulusSize_ptr);

/*
 * @brief          : eps_adapt_rsa_sign
 * @param[in/out]  : rndContext_ptr  - Pointer to the RND context buffer.
 * @param[in]      : UserContext_ptr  - noused(just adapt for cc seceng).
 * @param[in]      : UserPrivKey_ptr - A pointer to the private key data structure of the user.
 *                   The representation (pair or quintuple) and hence the
 *                   algorithm (CRT or not) is determined by the Private Key data
 *                   structure - using CC_BuildPrivKey or CC_BuildPrivKeyCRT determines
 *                   which algorithm will be used.
 * @param[in]      : hashFunc - The hash functions supported: SHA1, SHA-256
 * @param[in]      : MGF - The mask generation function (enum). Only for PKCS#1 v2.1
 *                   defines MGF1, so the only value allowed for v2.1 is CC_PKCS1_MGF1.
 * @param[in]      : SaltLen - The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only)
 *                   Typical lengths are 0 and hLen (20 for SHA1)
 *                   The maximum length allowed is NSize - hLen - 2.
 * @param[in]      : DataIn_ptr - A pointer to the data to sign.
 * @param[in]      : DataInSize - The size, in bytes, of the data to sign.
 * @param[out]     : Output_ptr - A pointer to the signature.
 *                   The buffer must be at least PrivKey_ptr->N.len bytes long
 *                   (that is, the size of the modulus in bytes).
 * @param[in,out]  : OutputSize_ptr - A pointer to the Signature Size value - the input value
 *                   is the signature buffer size allocated, the output value is
 *                   the signature size actually used.
 *                   The buffer must be at least PrivKey_ptr->N.len bytes long
 *                   (that is, the size of the modulus in bytes).
 * @param[in]      : PKCS1_ver - Ver 1.5 or 2.1, according to the functionality required
 * @note           : implements the RSASSA-PKCS1v15 algorithm and RSASSA-PSS algorithm
 */
CEXPORT_C CCError_t EPS_RSASign(
	CCRndContext_t           *rndContext_ptr,
	CCRsaPrivUserContext_t   *UserContext_ptr,
	CCRsaUserPrivKey_t       *UserPrivKey_ptr,
	CCRsaHashOpMode_t         rsaHashMode,
	CCPkcs1Mgf_t              MGF,
	size_t                    SaltLen,
	uint8_t                  *DataIn_ptr,
	size_t                    DataInSize,
	uint8_t                  *Output_ptr,
	uint16_t                 *OutputSize_ptr,
	CCPkcs1Version_t          PKCS1_ver);

/*
 * @brief          : eps_adapt_rsa_sign_client
 * @param[in/out]  : rndContext_ptr  - Pointer to the RND context buffer.
 * @param[in]      : UserContext_ptr  - noused(just adapt for cc seceng).
 * @param[in]      : UserPrivKey_ptr - A pointer to the private key data structure of the user.
 *                   The representation (pair or quintuple) and hence the
 *                   algorithm (CRT or not) is determined by the Private Key data
 *                   structure - using CC_BuildPrivKey or CC_BuildPrivKeyCRT determines
 *                   which algorithm will be used.
 * @param[in]      : hashFunc - The hash functions supported: SHA1, SHA-256
 * @param[in]      : MGF - The mask generation function (enum). Only for PKCS#1 v2.1
 *                   defines MGF1, so the only value allowed for v2.1 is CC_PKCS1_MGF1.
 * @param[in]      : SaltLen - The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only)
 *                   Typical lengths are 0 and hLen (20 for SHA1)
 *                   The maximum length allowed is NSize - hLen - 2.
 * @param[in]      : DataIn_ptr - A pointer to the data to sign.
 * @param[in]      : DataInSize - The size, in bytes, of the data to sign.
 * @param[out]     : Output_ptr - A pointer to the signature.
 *                   The buffer must be at least PrivKey_ptr->N.len bytes long
 *                   (that is, the size of the modulus in bytes).
 * @param[in,out]  : OutputSize_ptr - A pointer to the Signature Size value - the input value
 *                   is the signature buffer size allocated, the output value is
 *                   the signature size actually used.
 *                   The buffer must be at least PrivKey_ptr->N.len bytes long
 *                   (that is, the size of the modulus in bytes).
 * @param[in]      : PKCS1_ver - Ver 1.5 or 2.1, according to the functionality required
 * @note           : implements the RSASSA-PKCS1v15 algorithm and RSASSA-PSS algorithm
 *                   the PrivKey is encrypted, need decrypt before sign
 */
CEXPORT_C CCError_t EPS_RSASignClient(
	CCRndContext_t           *rndContext_ptr,
	CCRsaPrivUserContext_t   *userContext_ptr,
	CCRsaUserPrivKey_t       *UserPrivKey_ptr,
	CCRsaHashOpMode_t         rsaHashMode,
	CCPkcs1Mgf_t              MGF,
	size_t                    SaltLen,
	uint8_t                  *DataIn_ptr,
	size_t                    DataInSize,
	uint8_t                  *Output_ptr,
	uint16_t                 *OutputSize_ptr,
	CCPkcs1Version_t          PKCS1_ver);

/*
 * @brief          : eps_adapt_rsa_verify
 * @param[in/out]  : rndContext_ptr - Pointer to the RND context buffer.
 * @param[in]      : UserContext_ptr - noused(just adapt for cc seceng).
 * @param[in]      : UserPrivKey_ptr - A pointer to the private key data structure of the user.
 *                   The representation (pair or quintuple) and hence the
 *                   algorithm (CRT or not) is determined by the Private Key data
 *                   structure - using CC_BuildPrivKey or CC_BuildPrivKeyCRT determines
 *                   which algorithm will be used.
 * @param[in]      : hashFunc - The hash functions supported: SHA1, SHA-256
 * @param[in]      : MGF - The mask generation function (enum). Only for PKCS#1 v2.1
 *                   defines MGF1, so the only value allowed for v2.1 is CC_PKCS1_MGF1.
 * @param[in]      : SaltLen - The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only)
 *                   Typical lengths are 0 and hLen (20 for SHA1)
 *                   The maximum length allowed is NSize - hLen - 2.
 * @param[in]      : DataIn_ptr - A pointer to the data to sign.
 * @param[in]      : DataInSize - The size, in bytes, of the data to sign.
 * @param[out]     ：Output_ptr - A pointer to the signature.
 *                   The buffer must be at least PrivKey_ptr->N.len bytes long
 *                   (that is, the size of the modulus in bytes).
 * @param[in,out]  : OutputSize_ptr - A pointer to the Signature Size value - the input value
 *                   is the signature buffer size allocated, the output value is
 *                   the signature size actually used.
 *                   The buffer must be at least PrivKey_ptr->N.len bytes long
 *                   (that is, the size of the modulus in bytes).
 * @param[in]      : PKCS1_ver - Ver 1.5 or 2.1, according to the functionality required
 * @note           : implements the RSASSA-PKCS1v15 algorithm and RSASSA-PSS algorithm
 */
CEXPORT_C CCError_t EPS_RSAVerify(
	CCRsaPubUserContext_t    *UserContext_ptr,
	CCRsaUserPubKey_t        *UserPubKey_ptr,
	CCRsaHashOpMode_t         rsaHashMode,
	CCPkcs1Mgf_t              MGF,
	size_t                    SaltLen,
	uint8_t                  *DataIn_ptr,
	size_t                    DataInSize,
	uint8_t                  *Sig_ptr,
	CCPkcs1Version_t          PKCS1_ver);

#endif
