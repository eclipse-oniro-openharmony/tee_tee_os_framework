/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description  : adapt dx RSA interface, achieve RSA signature and signature verification.
 * Author       : z00293770
 * Create       : 2018/12/18
 */
#include <adapt_rsa.h>
#include <api_utils.h>
#include "api_rsa.h"
#include "hal_rsa.h"
#include "common_utils.h"
#include <pal_log.h>
#include <pal_libc.h>
#include <sec_utils.h>

/* set the module to which the file belongs, each .C file needs to be configured */
#define BSP_THIS_MODULE BSP_MODULE_RSA

#define ORG_SIGN        0x5
#define CLIENT_SIGN     0xA

static err_bsp_t EPS_RSAGenKeyPairParamCheck(u8                 *PubExp_ptr,
					     size_t              PubExpSizeInBytes,
					     size_t              KeySize,
					     CCRsaUserPrivKey_t *pCcUserPrivKey,
					     CCRsaUserPubKey_t  *pCcUserPubKey)
{
	if (!PubExp_ptr)
		return CC_RSA_INVALID_EXPONENT_POINTER_ERROR;

	if (!pCcUserPrivKey)
		return CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

	if (!pCcUserPubKey)
		return CC_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

	if (PubExpSizeInBytes > CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
		return CC_RSA_INVALID_EXPONENT_SIZE;

	if ((KeySize < CC_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
	    (KeySize > CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS) ||
	    (KeySize % CC_RSA_VALID_KEY_SIZE_MULTIPLE_VALUE_IN_BITS))
		return CC_RSA_INVALID_MODULUS_SIZE;

	return BSP_RET_OK;
}

/*
 * @brief: EPS_RSAGenKeyPair
 * @param[in/out]  rndContext_ptr        - noused(just adapt for cc seceng).
 * @param[in]      PubExp_ptr            - The pointer to the public exponent (public key),( big endian )
 * @param[in]      PubExpSizeInBytes     - The public exponent size in bytes.
 * @param[in]      KeySize               - The size of the key in bits. Supported sizes are 256 bit multiples
 *					   between 512 - 4096;
 * @param[out]     pCcUserPrivKey        - A pointer to the private key structure.
 *					   This structure is used as input to the CC_RsaPrimDecrypt API.
 *					   the keydata in the structure is in little endian.
 * @param[out]     pCcUserPubKey         - A pointer to the public key structure.
 *					   This structure is used as input to the CC_RsaPrimEncrypt API.
 *					   the keydata in the structure is in little endian.
 * @param[in]      KeyGenData_ptr        - noused(just adapt for cc seceng).
 * @param[in]      pFipsCtx              - noused(just adapt for cc seceng).
 * @return:   ::CCError_t error code
 *		CC_OK,
 *		CC_RSA_INVALID_EXPONENT_POINTER_ERROR,
 *		CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
 *		CC_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
 *		CC_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
 *		CC_RSA_INVALID_MODULUS_SIZE,
 *		CC_RSA_INVALID_EXPONENT_SIZE
 *		other error code : refer to errcode_e in file <hieps_seceng_errno.h>
 * @note:       generates a Pair of public and private keys on non CRT mode
 */
CEXPORT_C CCError_t EPS_RSAGenKeyPair(CCRndContext_t       *rndContext_ptr,
				      u8                   *PubExp_ptr,
				      size_t                PubExpSizeInBytes,
				      size_t                KeySize,
				      CCRsaUserPrivKey_t   *pCcUserPrivKey,
				      CCRsaUserPubKey_t    *pCcUserPubKey,
				      CCRsaKgData_t        *KeyGenData_ptr,
				      CCRsaKgFipsContext_t *pFipsCtx)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);
	errno_t libc_ret;
	api_param_s api_key = {0};
	hal_rsa_key_s std_key = {0};
	CCRsaPubKey_t *ppub_key = NULL;
	CCRsaPrivKey_t *ppriv_key = NULL;

	UNUSED(rndContext_ptr);
	UNUSED(KeyGenData_ptr);
	UNUSED(pFipsCtx);

	ret = EPS_RSAGenKeyPairParamCheck(PubExp_ptr, PubExpSizeInBytes, KeySize, pCcUserPrivKey, pCcUserPubKey);
	PAL_ERR_RETURN(ret);

	/* set the public and private key structure pointers */
	(void)memset_s(pCcUserPrivKey, sizeof(*pCcUserPrivKey), 0, sizeof(*pCcUserPrivKey));
	(void)memset_s(pCcUserPubKey, sizeof(*pCcUserPubKey), 0, sizeof(*pCcUserPubKey));

	ppub_key  = (CCRsaPubKey_t *)pCcUserPubKey->PublicKeyDbBuff;
	ppriv_key = (CCRsaPrivKey_t *)pCcUserPrivKey->PrivateKeyDbBuff;

	/* set key structure */
	api_key.operation_mode = OPERATION_RSA_GEN_KEY;
	api_key.sub_mode = ALG_RSA_STD_KEY;
	api_key.object = &std_key;
	std_key.width = (u32)KeySize;
	std_key.elen = SIZE_ALIGN_IN_WORD((u32)PubExpSizeInBytes);
	libc_ret = memcpy_s(((u8 *)(ppub_key->e) + std_key.elen - (u32)PubExpSizeInBytes),
			    (u32)PubExpSizeInBytes, PubExp_ptr, (u32)PubExpSizeInBytes);
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), err_return);
	std_key.pe = (u8 *)(ppub_key->e);
	std_key.pn = (u8 *)(ppub_key->n);
	std_key.pd = (u8 *)(ppriv_key->PriveKeyDb.NonCrt.d);

	/* call the api to generate non-CRT keypair */
	ret = api_rsa_gen_keypair(&api_key);
	PAL_ERR_GOTO(ret, err_return);

	/* convert stdKey from big endian to little endian */
	ret = sec_convert_big_to_little_endian(std_key.pe, CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       std_key.pe, std_key.elen);
	PAL_ERR_GOTO(ret, err_return);
	ret = sec_convert_big_to_little_endian(std_key.pn, CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       std_key.pn, BIT2BYTE(std_key.width));
	PAL_ERR_GOTO(ret, err_return);
	ret = sec_convert_big_to_little_endian(std_key.pd, CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       std_key.pd, BIT2BYTE(std_key.width));
	PAL_ERR_GOTO(ret, err_return);

	/* set the public key structure */
	pCcUserPubKey->valid_tag  = CC_RSA_PUB_KEY_VALIDATION_TAG;
	ppub_key->eSizeInBits = BYTE2BIT(std_key.elen);
	ppub_key->nSizeInBits = std_key.width;

	/* set the private key structure */
	pCcUserPrivKey->valid_tag = CC_RSA_PRIV_KEY_VALIDATION_TAG;
	ppriv_key->OperationMode = CC_RSA_NoCrt;
	ppriv_key->KeySource = CC_RSA_InternalKey;
	libc_ret = memcpy_s((u8 *)(ppriv_key->n), BIT2BYTE(std_key.width), std_key.pn, BIT2BYTE(std_key.width));
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), err_return);
	ppriv_key->nSizeInBits = std_key.width;
	libc_ret = memcpy_s((u8 *)(ppriv_key->PriveKeyDb.NonCrt.e), std_key.elen, std_key.pe, std_key.elen);
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), err_return);
	ppriv_key->PriveKeyDb.NonCrt.eSizeInBits = BYTE2BIT(std_key.elen);
	ppriv_key->PriveKeyDb.NonCrt.dSizeInBits = std_key.width;

err_return:
	if (ret != BSP_RET_OK)
		(void)memset_s(pCcUserPrivKey, sizeof(*pCcUserPrivKey), 0, sizeof(*pCcUserPrivKey));

	PAL_ERR_RETURN(ret);
	return CC_OK;
}

/*
 * @brief      : EPS_RSAGenKeyPairCRT
 * @param[in/out] rndContext_ptr        - noused(just adapt for cc seceng).
 * @param[in]     PubExp_ptr            - The pointer to the public exponent (public key),( big endian )
 * @param[in]     PubExpSizeInBytes     - The public exponent size in bytes.
 * @param[in]     KeySize               - The size of the key in bits. Supported sizes are 256 bit multiples
 *					  between 512 - 4096;
 * @param[out]    pCcUserPrivKey        - A pointer to the private key structure.
 *					  This structure is used as input to the CC_RsaPrimDecrypt API.
 *					  the keydata in the structure is in little endian.
 * @param[out]    pCcUserPubKey         - A pointer to the public key structure.
 *					  This structure is used as input to the CC_RsaPrimEncrypt API.
 *					  the keydata in the structure is in little endian.
 * @param[in]     KeyGenData_ptr        - noused(just adapt for cc seceng).
 * @param[in]     pFipsCtx              - noused(just adapt for cc seceng).
 * @return:   ::CCError_t error code
 *		CC_OK,
 *		CC_RSA_INVALID_EXPONENT_POINTER_ERROR,
 *		CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
 *		CC_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
 *		CC_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
 *		CC_RSA_INVALID_MODULUS_SIZE,
 *		CC_RSA_INVALID_EXPONENT_SIZE
 *		other error code : refer to errcode_e in file <hieps_seceng_errno.h>
 * @note       :generates a Pair of public and private keys on CRT mode.
 */
CEXPORT_C CCError_t EPS_RSAGenKeyPairCRT(CCRndContext_t       *rndContext_ptr,
					 u8                   *PubExp_ptr,
					 size_t                PubExpSizeInBytes,
					 size_t                KeySize,
					 CCRsaUserPrivKey_t   *pCcUserPrivKey,
					 CCRsaUserPubKey_t    *pCcUserPubKey,
					 CCRsaKgData_t        *KeyGenData_ptr,
					 CCRsaKgFipsContext_t *pFipsCtx)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);
	errno_t libc_ret = EINVAL;
	api_param_s api_key = {0};
	hal_rsa_crtkey_s crt_key = {0};
	CCRsaPubKey_t  *ppub_key = NULL;
	CCRsaPrivKey_t *ppriv_key = NULL;
	u32 crtlen = CRT_PRIVKEY_LEN(BYTE2BIT((u32)KeySize));

	UNUSED(rndContext_ptr);
	UNUSED(KeyGenData_ptr);
	UNUSED(pFipsCtx);

	ret = EPS_RSAGenKeyPairParamCheck(PubExp_ptr, PubExpSizeInBytes, KeySize, pCcUserPrivKey, pCcUserPubKey);
	PAL_ERR_RETURN(ret);

	/* set the public and private key structure pointers */
	(void)memset_s(pCcUserPrivKey, sizeof(*pCcUserPrivKey), 0, sizeof(*pCcUserPrivKey));
	(void)memset_s(pCcUserPubKey, sizeof(*pCcUserPubKey), 0, sizeof(*pCcUserPubKey));

	ppub_key  = (CCRsaPubKey_t *)pCcUserPubKey->PublicKeyDbBuff;
	ppriv_key = (CCRsaPrivKey_t *)pCcUserPrivKey->PrivateKeyDbBuff;

	/* set key structure */
	api_key.operation_mode = OPERATION_RSA_GEN_KEY;
	api_key.sub_mode = ALG_RSA_CRT_KEY;
	api_key.object = &crt_key;
	crt_key.width = (u32)KeySize;
	crt_key.elen = SIZE_ALIGN_IN_WORD((u32)PubExpSizeInBytes);
	libc_ret = memcpy_s(((u8 *)(ppub_key->e) + crt_key.elen - (u32)PubExpSizeInBytes),
			    (u32)PubExpSizeInBytes, PubExp_ptr, (u32)PubExpSizeInBytes);
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), err_return);
	crt_key.pe = (u8 *)(ppub_key->e);
	crt_key.pn = (u8 *)(ppub_key->n);
	crt_key.pp = (u8 *)(ppriv_key->PriveKeyDb.Crt.P);
	crt_key.pq = (u8 *)(ppriv_key->PriveKeyDb.Crt.Q);
	crt_key.pdp = (u8 *)(ppriv_key->PriveKeyDb.Crt.dP);
	crt_key.pdq = (u8 *)(ppriv_key->PriveKeyDb.Crt.dQ);
	crt_key.pqinv = (u8 *)(ppriv_key->PriveKeyDb.Crt.qInv);
	ret = api_rsa_gen_keypair(&api_key);
	PAL_ERR_GOTO(ret, err_return);

	/* convert pubkey from big endian to little endian */
	ret = sec_convert_big_to_little_endian(crt_key.pe, CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       crt_key.pe, crt_key.elen);
	PAL_ERR_GOTO(ret, err_return);
	ret = sec_convert_big_to_little_endian(crt_key.pn, CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       crt_key.pn, BIT2BYTE(crt_key.width));
	PAL_ERR_GOTO(ret, err_return);
	ret = sec_convert_big_to_little_endian(crt_key.pp, CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE,
					       crt_key.pp, BIT2BYTE(crtlen));
	PAL_ERR_GOTO(ret, err_return);
	ret = sec_convert_big_to_little_endian(crt_key.pq, CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE,
					       crt_key.pq, BIT2BYTE(crtlen));
	PAL_ERR_GOTO(ret, err_return);
	ret = sec_convert_big_to_little_endian(crt_key.pdp, CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE,
					       crt_key.pdp, BIT2BYTE(crtlen));
	PAL_ERR_GOTO(ret, err_return);
	ret = sec_convert_big_to_little_endian(crt_key.pdq, CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE,
					       crt_key.pdq, BIT2BYTE(crtlen));
	PAL_ERR_GOTO(ret, err_return);
	ret = sec_convert_big_to_little_endian(crt_key.pqinv, CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE,
					       crt_key.pqinv, BIT2BYTE(crtlen));
	PAL_ERR_GOTO(ret, err_return);

	/* set the public key structure */
	pCcUserPubKey->valid_tag  = CC_RSA_PUB_KEY_VALIDATION_TAG;
	ppub_key->eSizeInBits = BYTE2BIT(crt_key.elen);
	ppub_key->nSizeInBits = KeySize;

	/* set the private key structure */
	pCcUserPrivKey->valid_tag = CC_RSA_PRIV_KEY_VALIDATION_TAG;
	ppriv_key->OperationMode = CC_RSA_Crt;
	ppriv_key->KeySource = CC_RSA_InternalKey;
	libc_ret = memcpy_s((u8 *)(ppriv_key->n), BIT2BYTE(crt_key.width), crt_key.pn, BIT2BYTE(crt_key.width));
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), err_return);
	ppriv_key->nSizeInBits = crt_key.width;
	ppriv_key->PriveKeyDb.Crt.PSizeInBits = crtlen;
	ppriv_key->PriveKeyDb.Crt.QSizeInBits = crtlen;
	ppriv_key->PriveKeyDb.Crt.dPSizeInBits = crtlen;
	ppriv_key->PriveKeyDb.Crt.dQSizeInBits = crtlen;
	ppriv_key->PriveKeyDb.Crt.qInvSizeInBits = crtlen;

err_return:
	if (ret != BSP_RET_OK)
		(void)memset_s(pCcUserPrivKey, sizeof(*pCcUserPrivKey), 0, sizeof(*pCcUserPrivKey));

	PAL_ERR_RETURN(ret);
	return CC_OK;
}

/*
 * @brief: EPS_RSABuildPubKey
 * @param[out] PubKey_ptr     - a pointer to the public key structure. This structure will be used as an input to
 *				the CC_RsaPrimEncrypt API. the keydata in the structure is in little endian.
 * @param[in]  Exponent_ptr   - a pointer to the exponent stream of bytes ( big endian ).
 * @param[in]  ExponentSize   - The size of the exponent in bytes.
 * @param[in]  Modulus_ptr    - a pointer to the modulus stream of bytes ( big endian ) the MS
 *				bit must be set to '1'.
 * @param[in]  ModulusSize    - The size of the modulus in bytes. Sizes supported according to
 *				used platform from 64 to 256 bytes and in some platforms up to 512 bytes.
 * @return:  ::CCError_t error code
 * @note:      populates a CCRsaPubKey_t structure with the provided modulus and exponent
 *	       the modulus and the exponent are presented in big endian.
 */
CEXPORT_C CCError_t EPS_RSABuildPubKey(CCRsaUserPubKey_t *UserPubKey_ptr,
				       u8                *Exponent_ptr,
				       size_t             ExponentSize,
				       u8                *Modulus_ptr,
				       size_t             ModulusSize)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);
	CCRsaPubKey_t  *ppub_key = NULL;

	if (!UserPubKey_ptr)
		return CC_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

	if (!Exponent_ptr)
		return CC_RSA_INVALID_EXPONENT_POINTER_ERROR;

	if (!Modulus_ptr)
		return CC_RSA_INVALID_MODULUS_POINTER_ERROR;

	if (ModulusSize > CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
		return CC_RSA_INVALID_MODULUS_SIZE;

	if (ExponentSize > CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
		return CC_RSA_INVALID_EXPONENT_SIZE;

	(void)memset_s(UserPubKey_ptr, sizeof(*UserPubKey_ptr), 0, sizeof(*UserPubKey_ptr));
	ppub_key  = (CCRsaPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;
	UserPubKey_ptr->valid_tag  = CC_RSA_PUB_KEY_VALIDATION_TAG;

	/* Copy and convert Exponent_ptr from big endian to little endian */
	ret = sec_convert_big_to_little_endian((u8 *)(ppub_key->e), CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       Exponent_ptr, ExponentSize);
	PAL_ERR_RETURN(ret);
	ppub_key->eSizeInBits = BYTE2BIT(SIZE_ALIGN_IN_WORD(ExponentSize));

	/* Copy and convert Modulus_ptr from big endian to little endian */
	ret = sec_convert_big_to_little_endian((u8 *)(ppub_key->n), CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       Modulus_ptr, ModulusSize);
	PAL_ERR_RETURN(ret);
	ppub_key->nSizeInBits = BYTE2BIT(SIZE_ALIGN_IN_WORD(ModulusSize));

	return CC_OK;
}

/*
 * @brief: EPS_RSABuildPrivKey
 * @param[out] UserPrivKey_ptr   - a pointer to the public key structure. this structure will be used as an input
 *				   to the CC_RsaPrimDecrypt API. the keydata in the structure is in little endian.
 * @param[in] PrivExponent_ptr   - a pointer to the private exponent stream of bytes ( big endian ).
 * @param[in] PrivExponentSize   - the size of the private exponent in bytes.
 * @param[in] Exponent_ptr       - a pointer to the exponent stream of bytes ( big endian ).
 * @param[in] ExponentSize       - the size of the exponent in bytes.
 * @param[in] Modulus_ptr        - a pointer to the modulus stream of bytes ( big endian ) the MS
 *				   bit must be set to '1'.
 * @param[in] ModulusSize        - the size of the modulus in bytes. Sizes supported according to
 *				   used platform from 64 to 256 bytes and in some platforms up to 512 bytes.
 *
 * @return: ::CCError_t error code
 * @note:     populates a CCRsaPrivKey_t structure with
 *	      the provided modulus and exponent, marking the key as a "non-CRT" key.
 */
CEXPORT_C CCError_t EPS_RSABuildPrivKey(CCRsaUserPrivKey_t  *UserPrivKey_ptr,
					u8                  *PrivExponent_ptr,
					size_t               PrivExponentSize,
					u8                  *PubExponent_ptr,
					size_t               PubExponentSize,
					u8                  *Modulus_ptr,
					size_t               ModulusSize)
{
	CCRsaPrivKey_t *ppriv_key = NULL;
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	/* ...... checking the key database handle pointer .................... */
	if (!UserPrivKey_ptr)
		return CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

	/* ...... checking the validity of the exponents pointers ........... */
	if (!PrivExponent_ptr)
		return CC_RSA_INVALID_EXPONENT_POINTER_ERROR;

	/* ...... checking the validity of the modulus pointer .............. */
	if (!Modulus_ptr)
		return CC_RSA_INVALID_MODULUS_POINTER_ERROR;

	/* checking the validity of the modulus size, private exponent can not be more than 256 bytes */
	if (ModulusSize > CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
		return CC_RSA_INVALID_MODULUS_SIZE;

	if (PrivExponentSize > CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
		return CC_RSA_INVALID_EXPONENT_SIZE;

	if (PubExponent_ptr &&
	    PubExponentSize > CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
		return CC_RSA_INVALID_EXPONENT_SIZE;

	(void)memset_s(UserPrivKey_ptr, sizeof(*UserPrivKey_ptr), 0, sizeof(*UserPrivKey_ptr));
	ppriv_key = (CCRsaPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;
	UserPrivKey_ptr->valid_tag = CC_RSA_PRIV_KEY_VALIDATION_TAG;

	/* set the mode to non CRT */
	ppriv_key->OperationMode = CC_RSA_NoCrt;
	/* set the key source as internal */
	ppriv_key->KeySource = CC_RSA_InternalKey;

	/* Copy and convert Modulus_ptr from big endian to little endian */
	ret = sec_convert_big_to_little_endian((u8 *)(ppriv_key->n), CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       Modulus_ptr, ModulusSize);
	PAL_ERR_RETURN(ret);
	ppriv_key->nSizeInBits = BYTE2BIT(SIZE_ALIGN_IN_WORD(ModulusSize));
	/* Copy and convert PubExponent_ptr from big endian to little endian */
	if (PubExponent_ptr) {
		ret = sec_convert_big_to_little_endian((u8 *)(ppriv_key->PriveKeyDb.NonCrt.e),
						       CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
						       PubExponent_ptr, PubExponentSize);
		PAL_ERR_RETURN(ret);
		ppriv_key->PriveKeyDb.NonCrt.eSizeInBits = BYTE2BIT(SIZE_ALIGN_IN_WORD(PubExponentSize));
	}
	/* Copy and convert PrivExponent_ptr from big endian to little endian */
	ret = sec_convert_big_to_little_endian((u8 *)(ppriv_key->PriveKeyDb.NonCrt.d),
					       CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       PrivExponent_ptr, PrivExponentSize);
	PAL_ERR_RETURN(ret);
	ppriv_key->PriveKeyDb.NonCrt.dSizeInBits = BYTE2BIT(SIZE_ALIGN_IN_WORD(PrivExponentSize));

	return CC_OK;
}

/*
 * @brief: EPS_RSABuildPrivKeyCRT
 * @param[out] UserPrivKey_ptr   - A pointer to the public key structure.
 *				   This structure is used as input to the CC_RsaPrimDecrypt API.
 *				   the keydata in the structure is in little endian.
 * @param[in]  P_ptr             - A pointer to the first factor stream of bytes (big-Endian format)
 * @param[in]  PSize             - The size of the first factor, in bytes.
 * @param[in]  Q_ptr             - A pointer to the second factor stream of bytes (big-Endian format)
 * @param[in]  QSize             - The size of the second factor, in bytes.
 * @param[in]  dP_ptr            - A pointer to the first factor's CRT exponent stream of bytes (big-Endian format)
 * @param[in]  dPSize            - The size of the first factor's CRT exponent, in bytes.
 * @param[in]  dQ_ptr            - A pointer to the second factor's CRT exponent stream of bytes (big-Endian format)
 * @param[in]  dQSize            - The size of the second factor's CRT exponent, in bytes.
 * @param[in]  qInv_ptr          - A pointer to the first CRT coefficient stream of bytes (big-Endian format)
 * @param[in]  qInvSize          - The size of the first CRT coefficient, in bytes.
 *
 * @return:  ::CCError_t error code
 * @note:      populates a CCRsaPrivKey_t structure with
 *	       the provided parameters, marking the key as a "CRT" key.
 */
CEXPORT_C CCError_t EPS_RSABuildPrivKeyCRT(CCRsaUserPrivKey_t *UserPrivKey_ptr,
					   u8      *P_ptr,
					   size_t   PSize,
					   u8      *Q_ptr,
					   size_t   QSize,
					   u8      *dP_ptr,
					   size_t   dPSize,
					   u8      *dQ_ptr,
					   size_t   dQSize,
					   u8      *qInv_ptr,
					   size_t   qInvSize)
{
	CCRsaPrivKey_t *ppriv_key = NULL;
	api_rsa_data_s a = {0};
	api_rsa_data_s b = {0};
	api_rsa_data_s c = {0};
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	/* ...... checking the key database handle pointer .................... */
	if (!UserPrivKey_ptr)
		return CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

	/* checking the first factor pointer validity */
	if (!P_ptr)
		return CC_RSA_INVALID_CRT_FIRST_FACTOR_POINTER_ERROR;

	/* checking the second factor pointer validity */
	if (!Q_ptr)
		return CC_RSA_INVALID_CRT_SECOND_FACTOR_POINTER_ERROR;

	/* checking the first factor exponent pointer validity */
	if (!dP_ptr)
		return CC_RSA_INVALID_CRT_FIRST_FACTOR_EXP_PTR_ERROR;

	/* checking the second factor exponent pointer validity */
	if (!dQ_ptr)
		return CC_RSA_INVALID_CRT_SECOND_FACTOR_EXP_PTR_ERROR;

	/* checking the CRT coefficient */
	if (!qInv_ptr)
		return CC_RSA_INVALID_CRT_COEFFICIENT_PTR_ERROR;

	/* checking the input sizes */
	if (PSize > CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES / 2 || /* 2: half */
	    QSize > CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES / 2)    /* 2: half */
		return CC_RSA_INVALID_CRT_PARAMETR_SIZE_ERROR;

	if (dPSize > PSize || dQSize > QSize || qInvSize > PSize)
		return CC_RSA_INVALID_CRT_PARAMETR_SIZE_ERROR;

	(void)memset_s(UserPrivKey_ptr, sizeof(*UserPrivKey_ptr), 0, sizeof(*UserPrivKey_ptr));
	ppriv_key = (CCRsaPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;
	UserPrivKey_ptr->valid_tag = CC_RSA_PRIV_KEY_VALIDATION_TAG;

	/* set the mode to non CRT */
	ppriv_key->OperationMode = CC_RSA_Crt;
	/* set the key source as internal */
	ppriv_key->KeySource = CC_RSA_InternalKey;

	/* Copy and convert P_ptr from big endian to little endian */
	ret = sec_convert_big_to_little_endian((u8 *)(ppriv_key->PriveKeyDb.Crt.P),
					       CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE, P_ptr, PSize);
	PAL_ERR_RETURN(ret);
	ppriv_key->PriveKeyDb.Crt.PSizeInBits = BYTE2BIT(SIZE_ALIGN_IN_WORD(PSize));
	/* Copy and convert Q_ptr from big endian to little endian */
	ret = sec_convert_big_to_little_endian((u8 *)(ppriv_key->PriveKeyDb.Crt.Q),
					       CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE, Q_ptr, QSize);
	PAL_ERR_RETURN(ret);
	ppriv_key->PriveKeyDb.Crt.QSizeInBits = BYTE2BIT(SIZE_ALIGN_IN_WORD(QSize));
	/* Copy and convert dP_ptr from big endian to little endian */
	ret = sec_convert_big_to_little_endian((u8 *)(ppriv_key->PriveKeyDb.Crt.dP),
					       CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE, dP_ptr, dPSize);
	PAL_ERR_RETURN(ret);
	ppriv_key->PriveKeyDb.Crt.dPSizeInBits = BYTE2BIT(SIZE_ALIGN_IN_WORD(dPSize));
	/* Copy and convert dQ_ptr from big endian to little endian */
	ret = sec_convert_big_to_little_endian((u8 *)(ppriv_key->PriveKeyDb.Crt.dQ),
					       CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE, dQ_ptr, dQSize);
	ppriv_key->PriveKeyDb.Crt.dQSizeInBits = BYTE2BIT(SIZE_ALIGN_IN_WORD(dQSize));
	PAL_ERR_RETURN(ret);
	/* Copy and convert qInv_ptr from big endian to little endian */
	ret = sec_convert_big_to_little_endian((u8 *)(ppriv_key->PriveKeyDb.Crt.qInv),
					       CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE, qInv_ptr, qInvSize);
	PAL_ERR_RETURN(ret);
	ppriv_key->PriveKeyDb.Crt.qInvSizeInBits = BYTE2BIT(SIZE_ALIGN_IN_WORD(qInvSize));

	/* calc n */
	a.pdata = P_ptr;
	a.size = (u32)(SIZE_ALIGN_IN_WORD(PSize));
	b.pdata = Q_ptr;
	b.size = (u32)(SIZE_ALIGN_IN_WORD(QSize));
	c.pdata = (u8 *)(ppriv_key->n);
	c.size = a.size + b.size;
	ppriv_key->nSizeInBits = BYTE2BIT(c.size);
	ret = api_rsa_bnmul(&a, &b, &c);
	PAL_ERR_RETURN(ret);
	/* Copy and convert n from big endian to little endian */
	ret = sec_convert_big_to_little_endian((u8 *)(ppriv_key->n), CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(ppriv_key->n), BIT2BYTE(ppriv_key->nSizeInBits));
	PAL_ERR_RETURN(ret);

	return CC_OK;
}

/*
 * @brief      : EPS_RSAGetPubKey
 * @param[in]     UserPubKey_ptr   - A pointer to the public key structure. This structure is used as input
 *				     to the CC_RsaPrimEncrypt API.(little-Endian format)
 *
 * @param[out]    Exponent_ptr     - A pointer to the exponent stream of bytes (Big-Endian format)
 * @param[in,out] ExponentSize_ptr - the size of the exponent buffer in bytes, it is updated to the
 *				     actual size of the exponent, in bytes.
 * @param[out]    Modulus_ptr      - A pointer to the modulus stream of bytes (Big-Endian format).
 *				     The MS (most significant) bit must be set to '1'.
 * @param[in,out] ModulusSize_ptr  - the size of the modulus buffer in bytes, it is updated to the
 *				     actual size of the modulus, in bytes.
 *
 * @return:     ::CCError_t error code
 * @note:         gets the e,n public key from the database.
 */
CEXPORT_C CCError_t EPS_RSAGetPubKey(CCRsaUserPubKey_t *UserPubKey_ptr,
				     u8                *Exponent_ptr,
				     u16               *ExponentSize_ptr,
				     u8                *Modulus_ptr,
				     u16               *ModulusSize_ptr)
{
	CCRsaPubKey_t *ppub_key = NULL;
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	/* ...... checking the key database handle pointer .................... */
	if (!UserPubKey_ptr)
		return CC_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

	/* ...... checking the validity of the exponent pointer ............... */
	if (!Exponent_ptr)
		return CC_RSA_INVALID_EXPONENT_POINTER_ERROR;

	/* ...... checking the validity of the modulus pointer .............. */
	if (!Modulus_ptr)
		return CC_RSA_INVALID_MODULUS_POINTER_ERROR;

	if (!ExponentSize_ptr)
		return CC_RSA_INVALID_EXP_BUFFER_SIZE_POINTER;

	if (!ModulusSize_ptr)
		return CC_RSA_INVALID_MOD_BUFFER_SIZE_POINTER;

	/* if the users TAG is illegal return an error - the context is invalid */
	if (UserPubKey_ptr->valid_tag != CC_RSA_PUB_KEY_VALIDATION_TAG)
		return CC_RSA_PUB_KEY_VALIDATION_TAG_ERROR;

	ppub_key = (CCRsaPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;

	/* convert stdKey from little endian to big endian */
	ret = sec_convert_little_to_big_endian(Exponent_ptr, *ExponentSize_ptr,
					       (u8 *)(ppub_key->e), BIT2BYTE(ppub_key->eSizeInBits));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian(Modulus_ptr, *ModulusSize_ptr,
					       (u8 *)(ppub_key->n), BIT2BYTE(ppub_key->nSizeInBits));
	PAL_ERR_RETURN(ret);
	*ExponentSize_ptr = BIT2BYTE(ppub_key->eSizeInBits);
	*ModulusSize_ptr = BIT2BYTE(ppub_key->nSizeInBits);

	return CC_OK;
}

static err_bsp_t EPS_RSAPubkeyConvert(CCRsaPubKey_t *pPubKey, api_rsa_key_s *pKey)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	PAL_CHECK_RETURN(!pPubKey, ERR_API(ERRCODE_NULL));

	/* convert pubkey from little endian to big endian */
	ret = sec_convert_little_to_big_endian((u8 *)(pPubKey->e), CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPubKey->e), BIT2BYTE(pPubKey->eSizeInBits));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian((u8 *)(pPubKey->n), CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPubKey->n), BIT2BYTE(pPubKey->nSizeInBits));
	PAL_ERR_RETURN(ret);

	pKey->key_type = ALG_RSA_STD_KEY;
	((hal_rsa_key_s *)pKey->key_info)->width = pPubKey->nSizeInBits;
	((hal_rsa_key_s *)pKey->key_info)->pe = (u8 *)(pPubKey->e);
	((hal_rsa_key_s *)pKey->key_info)->elen = BIT2BYTE(pPubKey->eSizeInBits);
	((hal_rsa_key_s *)pKey->key_info)->pn = (u8 *)(pPubKey->n);
	((hal_rsa_key_s *)pKey->key_info)->pd = NULL;

	return BSP_RET_OK;
}

static err_bsp_t EPS_RSAStdPrivkeyConvert(CCRsaPrivKey_t *pPrivKey, api_rsa_key_s *pKey)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	PAL_CHECK_RETURN(!pPrivKey, ERR_API(ERRCODE_NULL));

	/* convert pPrivKey from little endian to big endian */
	ret = sec_convert_little_to_big_endian((u8 *)(pPrivKey->PriveKeyDb.NonCrt.e),
					       CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPrivKey->PriveKeyDb.NonCrt.e),
					       BIT2BYTE(pPrivKey->PriveKeyDb.NonCrt.eSizeInBits));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian((u8 *)(pPrivKey->n), CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPrivKey->n), BIT2BYTE(pPrivKey->nSizeInBits));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian((u8 *)(pPrivKey->PriveKeyDb.NonCrt.d),
					       CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPrivKey->PriveKeyDb.NonCrt.d),
					       BIT2BYTE(pPrivKey->PriveKeyDb.NonCrt.dSizeInBits));
	PAL_ERR_RETURN(ret);

	pKey->key_type = ALG_RSA_STD_KEY;
	((hal_rsa_key_s *)pKey->key_info)->width = pPrivKey->nSizeInBits;
	((hal_rsa_key_s *)pKey->key_info)->pe = (u8 *)pPrivKey->PriveKeyDb.NonCrt.e;
	((hal_rsa_key_s *)pKey->key_info)->elen = BIT2BYTE(pPrivKey->PriveKeyDb.NonCrt.eSizeInBits);
	((hal_rsa_key_s *)pKey->key_info)->pn = (u8 *)(pPrivKey->n);
	((hal_rsa_key_s *)pKey->key_info)->pd = (u8 *)(pPrivKey->PriveKeyDb.NonCrt.d);

	return BSP_RET_OK;
}

static err_bsp_t EPS_RSACrtPrivkeyConvert(CCRsaPrivKey_t *pPrivKey, api_rsa_key_s *pKey)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	PAL_CHECK_RETURN(!pPrivKey, ERR_API(ERRCODE_NULL));

	/* convert pPrivKey from little endian to big endian */
	ret = sec_convert_little_to_big_endian((u8 *)(pPrivKey->n), CC_RSA_KEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPrivKey->n), BIT2BYTE(pPrivKey->nSizeInBits));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian((u8 *)(pPrivKey->PriveKeyDb.Crt.P),
					       CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPrivKey->PriveKeyDb.Crt.P),
					       BIT2BYTE(pPrivKey->PriveKeyDb.Crt.PSizeInBits));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian((u8 *)(pPrivKey->PriveKeyDb.Crt.Q),
					       CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPrivKey->PriveKeyDb.Crt.Q),
					       BIT2BYTE(pPrivKey->PriveKeyDb.Crt.QSizeInBits));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian((u8 *)(pPrivKey->PriveKeyDb.Crt.dP),
					       CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPrivKey->PriveKeyDb.Crt.dP),
					       BIT2BYTE(pPrivKey->PriveKeyDb.Crt.dPSizeInBits));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian((u8 *)(pPrivKey->PriveKeyDb.Crt.dQ),
					       CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPrivKey->PriveKeyDb.Crt.dQ),
					       BIT2BYTE(pPrivKey->PriveKeyDb.Crt.dQSizeInBits));
	PAL_ERR_RETURN(ret);
	ret = sec_convert_little_to_big_endian((u8 *)(pPrivKey->PriveKeyDb.Crt.qInv),
					       CC_RSA_CRTKEY_BUFFER_SIZE_IN_BYTE,
					       (u8 *)(pPrivKey->PriveKeyDb.Crt.qInv),
					       BIT2BYTE(pPrivKey->PriveKeyDb.Crt.qInvSizeInBits));
	PAL_ERR_RETURN(ret);

	pKey->key_type = ALG_RSA_CRT_KEY;
	((hal_rsa_crtkey_s *)pKey->key_info)->width = pPrivKey->nSizeInBits;
	((hal_rsa_crtkey_s *)pKey->key_info)->pe = NULL;
	((hal_rsa_crtkey_s *)pKey->key_info)->elen = 0;
	((hal_rsa_crtkey_s *)pKey->key_info)->pn = (u8 *)(pPrivKey->n);
	((hal_rsa_crtkey_s *)pKey->key_info)->pp = (u8 *)(pPrivKey->PriveKeyDb.Crt.P);
	((hal_rsa_crtkey_s *)pKey->key_info)->pq = (u8 *)(pPrivKey->PriveKeyDb.Crt.Q);
	((hal_rsa_crtkey_s *)pKey->key_info)->pdp = (u8 *)(pPrivKey->PriveKeyDb.Crt.dP);
	((hal_rsa_crtkey_s *)pKey->key_info)->pdq = (u8 *)(pPrivKey->PriveKeyDb.Crt.dQ);
	((hal_rsa_crtkey_s *)pKey->key_info)->pqinv = (u8 *)(pPrivKey->PriveKeyDb.Crt.qInv);

	return BSP_RET_OK;
}

static err_bsp_t EPS_RSASignParamCheck(
	CCRsaUserPrivKey_t *UserPrivKey_ptr,
	CCRsaHashOpMode_t   rsaHashMode,
	CCPkcs1Mgf_t        MGF,
	u8                 *DataIn_ptr,
	size_t              DataInSize,
	u8                 *Output_ptr,
	u16                *OutputSize_ptr,
	CCPkcs1Version_t    PKCS1_ver)
{
	if (!UserPrivKey_ptr)
		return CC_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

	if (rsaHashMode >= CC_RSA_HASH_NumOfModes)
		return CC_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

	if (MGF >= CC_RSA_NumOfMGFFunctions)
		return CC_RSA_MGF_ILLEGAL_ARG_ERROR;

	if (PKCS1_ver >= CC_RSA_NumOf_PKCS1_versions)
		return CC_RSA_PKCS1_VER_ARG_ERROR;

	if (UserPrivKey_ptr->valid_tag != CC_RSA_PRIV_KEY_VALIDATION_TAG)
		return CC_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

	if (PKCS1_ver == CC_PKCS1_VER21 && rsaHashMode == CC_RSA_HASH_MD5_mode)
		return CC_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

	if (!DataIn_ptr && DataInSize)
		return CC_RSA_DATA_POINTER_INVALID_ERROR;

	if (DataInSize >= (1 << 29)) /* 29: input data size must less than 2^29 */
		return  CC_RSA_INVALID_MESSAGE_DATA_SIZE;

	if (!Output_ptr)
		return  CC_RSA_INVALID_OUTPUT_POINTER_ERROR;

	if (!OutputSize_ptr)
		return  CC_RSA_INVALID_OUTPUT_SIZE_POINTER_ERROR;

	return BSP_RET_OK;
}

static err_bsp_t EPS_HashmodeTransfer(CCRsaHashOpMode_t ccHashMode,
				      u32 *epsHashMode)
{
	switch (ccHashMode) {
	case CC_RSA_HASH_SHA1_mode:
		*epsHashMode = HASH_SHA1_MODE;
		break;
	case CC_RSA_HASH_SHA256_mode:
		*epsHashMode = HASH_SHA256_MODE;
		break;
	case CC_RSA_After_SHA1_mode:
		*epsHashMode = HASH_AFTER_SHA1_MODE;
		break;
	case CC_RSA_After_SHA256_mode:
		*epsHashMode = HASH_AFTER_SHA256_MODE;
		break;
	default:
		PAL_ERROR("error ccHashMode = %d\n", ccHashMode);
		return ERR_DRV(ERRCODE_INVALID);
	}

	return BSP_RET_OK;
}

static err_bsp_t EPS_RSASignV15(
	u32                 SignFlag,
	CCRsaUserPrivKey_t *UserPrivKey_ptr,
	CCRsaHashOpMode_t   rsaHashMode,
	u8                 *DataIn_ptr,
	size_t              DataInSize,
	u8                 *Output_ptr,
	u16                *OutputSize_ptr)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);
	api_param_s sign = {0};
	api_rsa_pkcs_v1_5_sign_s sign_v15 = {0};
	api_rsa_key_s api_key = {0};
	hal_rsa_key_s std_key = {0};
	hal_rsa_crtkey_s crt_key = {0};
	CCRsaPrivKey_t *ppriv_key = (CCRsaPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

	sign.operation_mode = OPERATION_RSA_SIGN;
	if (SignFlag == CLIENT_SIGN)
		sign.sub_mode = ALG_RSASSA_PKCS1_V15_CLIENTSK;
	else
		sign.sub_mode = ALG_RSASSA_PKCS1_V15;

	sign.object = &sign_v15;
	sign_v15.pkey_s = &api_key;

	ret = EPS_HashmodeTransfer(rsaHashMode, &sign_v15.hashmode);
	PAL_ERR_RETURN(ret);

	if (ppriv_key->OperationMode == CC_RSA_NoCrt) {
		api_key.key_info = &std_key;
		ret = EPS_RSAStdPrivkeyConvert(ppriv_key, sign_v15.pkey_s);
		PAL_ERR_RETURN(ret);
	} else {
		api_key.key_info = &crt_key;
		ret = EPS_RSACrtPrivkeyConvert(ppriv_key, sign_v15.pkey_s);
		PAL_ERR_RETURN(ret);
	}

	sign_v15.inlen = (u32)DataInSize;
	sign_v15.pdin = DataIn_ptr;
	sign_v15.psign = Output_ptr;
	ret = api_rsa_sign(&sign);
	PAL_ERR_RETURN(ret);
	*OutputSize_ptr = BIT2BYTE(ppriv_key->nSizeInBits);

	return ret;
}

static err_bsp_t EPS_RSASignPss(u32 SignFlag, CCRsaUserPrivKey_t *UserPrivKey_ptr,
				CCRsaHashOpMode_t rsaHashMode, CCPkcs1Mgf_t MGF,
				size_t SaltLen, u8 *DataIn_ptr, size_t DataInSize,
				u8 *Output_ptr, u16 *OutputSize_ptr)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);
	api_param_s sign = {0};
	api_rsa_pss_sign_s sign_pss = {0};
	api_rsa_key_s api_key = {0};
	hal_rsa_key_s std_key = {0};
	hal_rsa_crtkey_s crt_key = {0};
	CCRsaPrivKey_t *ppriv_key = (CCRsaPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

	sign.operation_mode = OPERATION_RSA_SIGN;
	sign.sub_mode = ALG_RSASSA_PKCS1_PSS;
	if (SignFlag == CLIENT_SIGN)
		sign.sub_mode = ALG_RSASSA_PKCS1_PSS_CLIENTSK;
	else
		sign.sub_mode = ALG_RSASSA_PKCS1_PSS;
	sign.object = &sign_pss;
	sign_pss.pkey_s = &api_key;

	ret = EPS_HashmodeTransfer(rsaHashMode, &sign_pss.hashmode);
	PAL_ERR_RETURN(ret);

	/*  Set MGF indication */
	if (MGF == CC_PKCS1_MGF1) {
		sign_pss.MGFmode = MGF_PKCS1_MGF1;
	} else {
		PAL_ERROR("error MGF = %d\n", MGF);
		return ERR_DRV(ERRCODE_INVALID);
	}

	if (CC_RSA_NoCrt == ppriv_key->OperationMode) {
		api_key.key_info = &std_key;
		ret = EPS_RSAStdPrivkeyConvert(ppriv_key, sign_pss.pkey_s);
		PAL_ERR_RETURN(ret);
	} else {
		api_key.key_info = &crt_key;
		ret = EPS_RSACrtPrivkeyConvert(ppriv_key, sign_pss.pkey_s);
		PAL_ERR_RETURN(ret);
	}
	sign_pss.saltlen = (u32)SaltLen;
	sign_pss.inlen = (u32)DataInSize;
	sign_pss.pdin = DataIn_ptr;
	sign_pss.psign = Output_ptr;
	ret = api_rsa_sign(&sign);
	PAL_ERR_RETURN(ret);
	*OutputSize_ptr = BIT2BYTE(ppriv_key->nSizeInBits);

	return ret;
}

/*
 * @brief: eps_adapt_rsa_sign
 *
 * @param[in/out] rndContext_ptr    - Pointer to the RND context buffer.
 * @param[in]     UserContext_ptr   - noused(just adapt for cc seceng).
 * @param[in]     UserPrivKey_ptr   - A pointer to the private key data structure of the user.
 *				      The representation (pair or quintuple) and hence the
 *				      algorithm (CRT or not) is determined by the Private Key data
 *				      structure - using CC_BuildPrivKey or CC_BuildPrivKeyCRT determines
 *				      which algorithm will be used.
 * @param[in]     hashFunc          - The hash functions supported: SHA1, SHA-256
 * @param[in]     MGF               - The mask generation function (enum). Only for PKCS#1 v2.1
 *				      defines MGF1, so the only value allowed for v2.1 is CC_PKCS1_MGF1.
 * @param[in]     SaltLen           - The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only)
 *				      Typical lengths are 0 and hLen (20 for SHA1)
 *				      The maximum length allowed is NSize - hLen - 2.
 * @param[in]     DataIn_ptr        - A pointer to the data to sign.
 * @param[in]     DataInSize        - The size, in bytes, of the data to sign.
 * @param[out]    Output_ptr        - A pointer to the signature.
 *				      The buffer must be at least PrivKey_ptr->N.len bytes long
 *				      (that is, the size of the modulus in bytes).
 * @param[in/out] OutputSize_ptr    - A pointer to the Signature Size value - the input value
 *				      is the signature buffer size allocated, the output value is
 *				      the signature size actually used.
 *				      The buffer must be at least PrivKey_ptr->N.len bytes long
 *				      (that is, the size of the modulus in bytes).
 * @param[in]     PKCS1_ver         - Ver 1.5 or 2.1, according to the functionality required
 *
 * @return:     ::CCError_t error code
 * @note:         implements the RSASSA-PKCS1v15 algorithm and RSASSA-PSS algorithm
 */
CEXPORT_C CCError_t EPS_RSASign(CCRndContext_t         *rndContext_ptr,
				CCRsaPrivUserContext_t *UserContext_ptr,
				CCRsaUserPrivKey_t     *UserPrivKey_ptr,
				CCRsaHashOpMode_t       rsaHashMode,
				CCPkcs1Mgf_t            MGF,
				size_t                  SaltLen,
				u8                     *DataIn_ptr,
				size_t                  DataInSize,
				u8                     *Output_ptr,
				u16                    *OutputSize_ptr,
				CCPkcs1Version_t        PKCS1_ver)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	UNUSED(rndContext_ptr);
	UNUSED(UserContext_ptr);

	ret = EPS_RSASignParamCheck(UserPrivKey_ptr, rsaHashMode, MGF,
				    DataIn_ptr, DataInSize, Output_ptr, OutputSize_ptr, PKCS1_ver);
	PAL_ERR_RETURN(ret);

	/* Switch to appropriate pkcs1_version */
	switch (PKCS1_ver) {
	case CC_PKCS1_VER15:
		ret = EPS_RSASignV15(ORG_SIGN, UserPrivKey_ptr, rsaHashMode,
				     DataIn_ptr, DataInSize, Output_ptr, OutputSize_ptr);
		PAL_ERR_RETURN(ret);
		break;
	case CC_PKCS1_VER21:
		ret = EPS_RSASignPss(ORG_SIGN, UserPrivKey_ptr, rsaHashMode, MGF, SaltLen,
				     DataIn_ptr, DataInSize, Output_ptr, OutputSize_ptr);
		PAL_ERR_RETURN(ret);
		break;
	default:
		ret = CC_RSA_PKCS1_VER_ARG_ERROR;
		break;
	}

	PAL_ERR_RETURN(ret);
	return CC_OK;
}

/*
 * @brief: eps_adapt_rsa_sign_client
 *
 * @param[in/out] rndContext_ptr    - Pointer to the RND context buffer.
 * @param[in]     UserContext_ptr   - noused(just adapt for cc seceng).
 * @param[in]     UserPrivKey_ptr   - A pointer to the private key data structure of the user.
 *				      The representation (pair or quintuple) and hence the
 *				      algorithm (CRT or not) is determined by the Private Key data
 *				      structure - using CC_BuildPrivKey or CC_BuildPrivKeyCRT determines
 *				      which algorithm will be used.
 * @param[in]     hashFunc          - The hash functions supported: SHA1, SHA-256
 * @param[in]     MGF               - The mask generation function (enum). Only for PKCS#1 v2.1
 *				      defines MGF1, so the only value allowed for v2.1 is CC_PKCS1_MGF1.
 * @param[in]     SaltLen           - The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only)
 *				      Typical lengths are 0 and hLen (20 for SHA1)
 *				      The maximum length allowed is NSize - hLen - 2.
 * @param[in]     DataIn_ptr        - A pointer to the data to sign.
 * @param[in]     DataInSize        - The size, in bytes, of the data to sign.
 * @param[out]    Output_ptr        - A pointer to the signature.
 *				      The buffer must be at least PrivKey_ptr->N.len bytes long
 *				      (that is, the size of the modulus in bytes).
 * @param[in/out] OutputSize_ptr    - A pointer to the Signature Size value - the input value
 *				      is the signature buffer size allocated, the output value is
 *				      the signature size actually used.
 *				      The buffer must be at least PrivKey_ptr->N.len bytes long
 *				      (that is, the size of the modulus in bytes).
 * @param[in]     PKCS1_ver         - Ver 1.5 or 2.1, according to the functionality required
 *
 * @return:     ::CCError_t error code
 * @note:         implements the RSASSA-PKCS1v15 algorithm and RSASSA-PSS algorithm
 *		  the PrivKey is encrypted, need decrypt before sign
 */
CEXPORT_C CCError_t EPS_RSASignClient(CCRndContext_t         *rndContext_ptr,
				      CCRsaPrivUserContext_t *userContext_ptr,
				      CCRsaUserPrivKey_t     *UserPrivKey_ptr,
				      CCRsaHashOpMode_t       rsaHashMode,
				      CCPkcs1Mgf_t            MGF,
				      size_t                  SaltLen,
				      u8                     *DataIn_ptr,
				      size_t                  DataInSize,
				      u8                     *Output_ptr,
				      u16                    *OutputSize_ptr,
				      CCPkcs1Version_t        PKCS1_ver)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	UNUSED(rndContext_ptr);
	UNUSED(userContext_ptr);

	ret = EPS_RSASignParamCheck(UserPrivKey_ptr, rsaHashMode, MGF,
				    DataIn_ptr, DataInSize, Output_ptr, OutputSize_ptr, PKCS1_ver);
	PAL_ERR_RETURN(ret);

	/* Switch to appropriate pkcs1_version */
	switch (PKCS1_ver) {
	case CC_PKCS1_VER15:
		ret = EPS_RSASignV15(CLIENT_SIGN, UserPrivKey_ptr, rsaHashMode,
				     DataIn_ptr, DataInSize, Output_ptr, OutputSize_ptr);
		PAL_ERR_RETURN(ret);
		break;
	case CC_PKCS1_VER21:
		ret = EPS_RSASignPss(CLIENT_SIGN, UserPrivKey_ptr, rsaHashMode, MGF, SaltLen,
				     DataIn_ptr, DataInSize, Output_ptr, OutputSize_ptr);
		PAL_ERR_RETURN(ret);
		break;
	default:
		ret = CC_RSA_PKCS1_VER_ARG_ERROR;
		break;
	}

	PAL_ERR_RETURN(ret);
	return CC_OK;
}

static err_bsp_t EPS_RSAVerifyParamCheck(
	CCRsaUserPubKey_t *UserPubKey_ptr,
	CCRsaHashOpMode_t  rsaHashMode,
	CCPkcs1Mgf_t       MGF,
	u8                *DataIn_ptr,
	size_t             DataInSize,
	u8                *Sig_ptr,
	CCPkcs1Version_t   PKCS1_ver)
{
	if (!UserPubKey_ptr)
		return CC_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

	if (rsaHashMode >= CC_RSA_HASH_NumOfModes) {
		PAL_ERROR("rsaHashMode = %d\n", rsaHashMode);
		return CC_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
	}

	if (MGF >= CC_RSA_NumOfMGFFunctions)
		return CC_RSA_MGF_ILLEGAL_ARG_ERROR;

	if (PKCS1_ver >= CC_RSA_NumOf_PKCS1_versions)
		return CC_RSA_PKCS1_VER_ARG_ERROR;

	if (UserPubKey_ptr->valid_tag != CC_RSA_PUB_KEY_VALIDATION_TAG)
		return CC_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

	if (PKCS1_ver == CC_PKCS1_VER21 && rsaHashMode == CC_RSA_HASH_MD5_mode) {
		PAL_ERROR("PKCS1_ver = %d, rsaHashMode = %d\n", PKCS1_ver, rsaHashMode);
		return CC_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
	}

	if (!DataIn_ptr && DataInSize)
		return CC_RSA_DATA_POINTER_INVALID_ERROR;

	if (DataInSize >= (1 << 29)) /* 29: input data size must less than 2^29 */
		return  CC_RSA_INVALID_MESSAGE_DATA_SIZE;

	if (!Sig_ptr)
		return  CC_RSA_INVALID_SIGNATURE_BUFFER_POINTER;

	return BSP_RET_OK;
}

static err_bsp_t EPS_RSAVerifyV15(
	CCRsaUserPubKey_t *UserPubKey_ptr,
	CCRsaHashOpMode_t  rsaHashMode,
	u8                *DataIn_ptr,
	size_t             DataInSize,
	u8                *Sig_ptr)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);
	api_param_s verify = {0};
	api_rsa_pkcs_v1_5_sign_s verify_v15 = {0};
	api_rsa_key_s api_key = {0};
	hal_rsa_key_s std_key = {0};
	CCRsaPubKey_t *ppub_key = (CCRsaPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;

	verify.operation_mode = OPERATION_RSA_VERIFY;
	verify.sub_mode = ALG_RSASSA_PKCS1_V15;
	verify.object = &verify_v15;
	verify_v15.pkey_s = &api_key;

	ret = EPS_HashmodeTransfer(rsaHashMode, &verify_v15.hashmode);
	PAL_ERR_RETURN(ret);

	api_key.key_info = &std_key;
	ret = EPS_RSAPubkeyConvert(ppub_key, verify_v15.pkey_s);
	PAL_ERR_RETURN(ret);
	verify_v15.inlen = (u32)DataInSize;
	verify_v15.pdin = DataIn_ptr;
	verify_v15.psign = Sig_ptr;
	ret = api_rsa_verify(&verify);
	PAL_ERR_RETURN(ret);

	return ret;
}

static err_bsp_t EPS_RSAVerifyPss(
	CCRsaUserPubKey_t *UserPubKey_ptr,
	CCRsaHashOpMode_t  rsaHashMode,
	CCPkcs1Mgf_t       MGF,
	size_t             SaltLen,
	u8                *DataIn_ptr,
	size_t             DataInSize,
	u8                *Sig_ptr)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);
	api_param_s verify = {0};
	api_rsa_pss_sign_s verify_pss = {0};
	api_rsa_key_s api_key = {0};
	hal_rsa_key_s std_key = {0};
	CCRsaPubKey_t *ppub_key = (CCRsaPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;

	verify.operation_mode = OPERATION_RSA_VERIFY;
	verify.sub_mode = ALG_RSASSA_PKCS1_PSS;
	verify.object = &verify_pss;
	verify_pss.pkey_s = &api_key;

	ret = EPS_HashmodeTransfer(rsaHashMode, &verify_pss.hashmode);
	PAL_ERR_RETURN(ret);

	/* Set MGF indication */
	if (MGF == CC_PKCS1_MGF1) {
		verify_pss.MGFmode = MGF_PKCS1_MGF1;
	} else {
		PAL_ERROR("error MGF = %d\n", MGF);
		return ERR_DRV(ERRCODE_INVALID);
	}

	api_key.key_info = &std_key;
	ret = EPS_RSAPubkeyConvert(ppub_key, verify_pss.pkey_s);
	PAL_ERR_RETURN(ret);
	verify_pss.saltlen = (u32)SaltLen;
	verify_pss.inlen = (u32)DataInSize;
	verify_pss.pdin = DataIn_ptr;
	verify_pss.psign = Sig_ptr;
	ret = api_rsa_verify(&verify);
	PAL_ERR_RETURN(ret);

	return ret;
}

/*
 * @brief: eps_adapt_rsa_verify
 *
 * @param[in/out] rndContext_ptr    - Pointer to the RND context buffer.
 * @param[in]     UserContext_ptr   - noused(just adapt for cc seceng).
 * @param[in]     UserPrivKey_ptr   - A pointer to the private key data structure of the user.
 *				      The representation (pair or quintuple) and hence the
 *				      algorithm (CRT or not) is determined by the Private Key data
 *				      structure - using CC_BuildPrivKey or CC_BuildPrivKeyCRT determines
 *				      which algorithm will be used.
 * @param[in]     hashFunc          - The hash functions supported: SHA1, SHA-256
 * @param[in]     MGF               - The mask generation function (enum). Only for PKCS#1 v2.1
 *				      defines MGF1, so the only value allowed for v2.1 is CC_PKCS1_MGF1.
 * @param[in]     SaltLen           - The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only)
 *				      Typical lengths are 0 and hLen (20 for SHA1)
 *				      The maximum length allowed is NSize - hLen - 2.
 * @param[in]     DataIn_ptr        - A pointer to the data to sign.
 * @param[in]     DataInSize        - The size, in bytes, of the data to sign.
 * @param[out]    Output_ptr        - A pointer to the signature.
 *				      The buffer must be at least PrivKey_ptr->N.len bytes long
 *				      (that is, the size of the modulus in bytes).
 * @param[in/out] OutputSize_ptr    - A pointer to the Signature Size value - the input value
 *				      is the signature buffer size allocated, the output value is
 *				      the signature size actually used.
 *				      The buffer must be at least PrivKey_ptr->N.len bytes long
 *				      (that is, the size of the modulus in bytes).
 * @param[in]     PKCS1_ver         - Ver 1.5 or 2.1, according to the functionality required
 *
 * @return:     ::CCError_t error code
 * @note:         implements the RSASSA-PKCS1v15 algorithm and RSASSA-PSS algorithm
 */
CEXPORT_C CCError_t EPS_RSAVerify(CCRsaPubUserContext_t *UserContext_ptr,
				  CCRsaUserPubKey_t     *UserPubKey_ptr,
				  CCRsaHashOpMode_t      rsaHashMode,
				  CCPkcs1Mgf_t           MGF,
				  size_t                 SaltLen,
				  u8                    *DataIn_ptr,
				  size_t                 DataInSize,
				  u8                    *Sig_ptr,
				  CCPkcs1Version_t       PKCS1_ver)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	UNUSED(UserContext_ptr);

	ret = EPS_RSAVerifyParamCheck(UserPubKey_ptr, rsaHashMode, MGF,
				      DataIn_ptr, DataInSize, Sig_ptr, PKCS1_ver);
	PAL_ERR_RETURN(ret);

	/* Switch to appropriate pkcs1_version */
	switch (PKCS1_ver) {
	case CC_PKCS1_VER15:
		ret = EPS_RSAVerifyV15(UserPubKey_ptr, rsaHashMode, DataIn_ptr, DataInSize, Sig_ptr);
		break;
	case CC_PKCS1_VER21:
		ret = EPS_RSAVerifyPss(UserPubKey_ptr, rsaHashMode, MGF,
				       SaltLen, DataIn_ptr, DataInSize, Sig_ptr);
		break;
	default:
		PAL_ERROR("PKCS1_ver = %d\n", PKCS1_ver);
		ret = CC_RSA_PKCS1_VER_ARG_ERROR;
		break;
	}

	PAL_ERR_RETURN(ret);
	return CC_OK;
}

