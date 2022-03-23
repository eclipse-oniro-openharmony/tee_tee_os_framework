/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include "common_rsa_keypair_util.h"
#include "common_util_log.h"
#include "common_crypto_sym.h"



/************************************* Globals  *************************************/

uint8_t gNp[NP_SIZE_IN_BYTES] = {0};
DxRsaKeyNandNp_t gNAndNp = {0};
uint8_t gN[RSA_MOD_SIZE_IN_BYTES +1] = {0};


/**
* @brief The function reads RSA key from the file and returns its N and Np.
*
* @param[in] PemEncryptedFileName_ptr - file name of the key pair
* @param[in] pwdFileName - file name of the password
* @param[out] pNbuff - N  buffer
* @param[in/out] pNbuffSize - as input - max size of pNbuff
*                              as output - actual size of pNbuff
*/
/*********************************************************/
int32_t CC_CommonGetNbuffFromKeyPair(int8_t *PemEncryptedFileName_ptr, int8_t *pwdFileName, uint8_t *pNbuff, uint32_t *pNbuffSize)
{

	int32_t status = -1;
	uint8_t *pwd = NULL;
	RSA *rsa_pkey = NULL;
	int32_t i;

	if ((NULL == pNbuff) ||
	    (NULL == pNbuffSize) ||
	    (NULL == PemEncryptedFileName_ptr)) {
		return status;
	}
	if (*pNbuffSize != RSA_MOD_SIZE_IN_BYTES) {
		return status;
	}

	/* parse the passphrase for a given file */
	if ((NULL != pwdFileName)) {
        if (CC_CommonGetPassphrase(pwdFileName, &pwd) != 0) {
        	UTIL_LOG_ERR("Failed to retrieve pwd\n");
        	goto END;
		}
        }

	rsa_pkey = RSA_new();
	if (NULL == rsa_pkey) {
		UTIL_LOG_ERR("Failed RSA_new\n");
		goto END;
	}
	if (CC_CommonGetKeyPair (&rsa_pkey, PemEncryptedFileName_ptr, pwd) != 0) {
		UTIL_LOG_ERR("Cannot read RSA public key.\n");
		goto END;
	}

	/* get the modulus from BIGNUM to uint8_t* */
	BN_bn2bin(rsa_pkey->n, (uint8_t *)gN);
	UTIL_LOG_BYTE_BUFF("gN", gN, RSA_MOD_SIZE_IN_BYTES);

	/* copy the Np to the end of N */
	memcpy(pNbuff, gN, RSA_MOD_SIZE_IN_BYTES);
	*pNbuffSize = RSA_MOD_SIZE_IN_BYTES;
	status = 0;


	END:
	if (rsa_pkey != NULL) {
		RSA_free(rsa_pkey);
	}
	if (pwd != NULL) {
		free(pwd);
	}
	return status;
}



/**
* @brief The function reads RSA key from the file and returns its N and Np.
*
* @param[in] PemEncryptedFileName_ptr - file name of the key pair
* @param[in] pwdFileName - file name of the password
* @param[out] pNAndNp - N and Np buffer
* @param[in/out] pNAndNpSize - as input - max size of pNAndNp
*                              as output - actual size of pNAndNp
*/
/*********************************************************/
int32_t CC_CommonGetNAndNpFromKeyPair(int8_t *PemEncryptedFileName_ptr, int8_t *pwdFileName, uint8_t *pNAndNp, uint32_t *pNAndNpSize)
{

	int32_t status = -1;
	uint8_t *pwd = NULL;
	RSA *rsa_pkey = NULL;
	DxRsaKeyNandNp_t *pNandNpBuff = (DxRsaKeyNandNp_t *)pNAndNp;
	int32_t i;

	if ((NULL == pNAndNp) ||
	    (NULL == pNAndNpSize) ||
	    (NULL == PemEncryptedFileName_ptr)) {
		return status;
	}
	if (*pNAndNpSize != sizeof(DxRsaKeyNandNp_t)) {
		return status;
	}

	/* parse the passphrase for a given file */
	if ((NULL != pwdFileName)) {
		if (CC_CommonGetPassphrase(pwdFileName, &pwd) != 0) {
			UTIL_LOG_ERR("Failed to retrieve pwd %s\n", pwdFileName);
			goto END;
		}
	}

	rsa_pkey = RSA_new();

	if (NULL == rsa_pkey) {
		UTIL_LOG_ERR("Failed RSA_new\n");
		goto END;
	}
	if (CC_CommonGetKeyPair (&rsa_pkey, PemEncryptedFileName_ptr, pwd)  != 0) {
		UTIL_LOG_ERR("Cannot read RSA public key.\n");
		goto END;
	}

	/* get the modulus from BIGNUM to uint8_t* */
	BN_bn2bin(rsa_pkey->n, (uint8_t *)gN);

	/* calculate the Np, and get the output as BIGNUM*/
	if (CC_CommonRSACalculateNpInt(rsa_pkey->n, gNp, NP_BIN)) {
		UTIL_LOG_ERR("Failed creating Np\n");
		goto END;
	}

	/* copy the Np to the end of N */
	memcpy(pNandNpBuff->pNBuff, gN, RSA_MOD_SIZE_IN_BYTES);
	memcpy(pNandNpBuff->pNpBuff, gNp, NP_SIZE_IN_BYTES);
	*pNAndNpSize = (RSA_MOD_SIZE_IN_BYTES+NP_SIZE_IN_BYTES);
	UTIL_LOG_BYTE_BUFF("gN", gN, RSA_MOD_SIZE_IN_BYTES);
	UTIL_LOG_BYTE_BUFF("gNp", gNp, NP_SIZE_IN_BYTES);
	status = 0;


	END:
	if (rsa_pkey != NULL) {
		RSA_free(rsa_pkey);
	}
	if (pwd != NULL) {
		free(pwd);
	}
	return status;
}



/**
* @brief The function reads RSA key from the file and returns its N and Np.
*
* @param[in] pubKeyFileName_ptr - file name of the key pair
* @param[out] pNAndNp - N and Np buffer
* @param[in/out] pNAndNpSize - as input - max size of pNAndNp
*                              as output - actual size of pNAndNp
*/
/*********************************************************/
int32_t CC_CommonGetNAndNpFromPubKey(int8_t *pubKeyFileName_ptr, uint8_t *pNAndNp, uint32_t *pNAndNpSize)
{
	int32_t status = -1;
	int32_t i;
	RSA *rsa_pkey = NULL;
	DxRsaKeyNandNp_t *pNandNpBuff = (DxRsaKeyNandNp_t *)pNAndNp;

	if ((NULL == pNAndNp) ||
	    (NULL == pNAndNpSize) ||
	    (NULL == pubKeyFileName_ptr)) {
		return status;
	}
	if (*pNAndNpSize != sizeof(DxRsaKeyNandNp_t)) {
		return status;
	}
	rsa_pkey = RSA_new();
	if (NULL == rsa_pkey) {
		UTIL_LOG_ERR("Failed RSA_new\n");
		goto END;
	}
	if (CC_CommonGetPubKey (&rsa_pkey, pubKeyFileName_ptr) < 0) {
		UTIL_LOG_ERR("Cannot read RSA public key.\n");
		goto END;
	}

	/* get the modulus from BIGNUM to uint8_t* */
	BN_bn2bin(rsa_pkey->n, (uint8_t *)gN);

	/* calculate the Np, and get the output as BIGNUM*/
	if (CC_CommonRSACalculateNpInt(rsa_pkey->n, gNp, NP_BIN) != 0) {
		UTIL_LOG_ERR("Failed creating Np\n");
		goto END;
	}

	/* copy the Np to the end of N */
	memcpy(pNandNpBuff->pNBuff, gN, RSA_MOD_SIZE_IN_BYTES);
	memcpy(pNandNpBuff->pNpBuff, gNp, NP_SIZE_IN_BYTES);
	*pNAndNpSize = (RSA_MOD_SIZE_IN_BYTES+NP_SIZE_IN_BYTES);
	UTIL_LOG_BYTE_BUFF("gN", gN, RSA_MOD_SIZE_IN_BYTES);
	UTIL_LOG_BYTE_BUFF("gNp", gNp, NP_SIZE_IN_BYTES);
	status = 0;

	END:
	if (rsa_pkey != NULL) {
		RSA_free(rsa_pkey);
	}
	return status;
}


/**
* @brief The CC_CommonCalcHBKFromBuff calculates Np from given pNbuff.
*        Then calculates HASH both N and Np
*
* @param[in] pNBuff - the N - modulus buff
* @param[out] pHash - hash output
* @param[in] hashSize - hash output size
*/
/*********************************************************/
int32_t CC_CommonCalcHBKFromBuff(int8_t* pNBuff, uint8_t *pHash, int32_t hashSize)
{

	int32_t status = -1;
	int32_t i;
	BIGNUM *bn_n = NULL;

	memcpy((uint8_t *)&gNAndNp, pNBuff, RSA_MOD_SIZE_IN_BYTES);
	UTIL_LOG_BYTE_BUFF("gN", (uint8_t *)&gNAndNp, RSA_MOD_SIZE_IN_BYTES);

	/* calculate the Np */
	bn_n = BN_bin2bn(pNBuff, RSA_MOD_SIZE_IN_BYTES, bn_n);
	if (NULL == bn_n) {
		UTIL_LOG_ERR ("BN_bin2bn failed\n");
		return -1;
	}

	if (CC_CommonRSACalculateNpInt(bn_n, gNp, NP_BIN) != 0) {
		UTIL_LOG_ERR ("BN_bin2bn failed\n");
		goto END;
	}
	UTIL_LOG_BYTE_BUFF("gNp", gNp, NP_SIZE_IN_BYTES);

	/* copy the Np to the end of N and calc hash on both */
	memcpy(gNAndNp.pNpBuff, gNp, NP_SIZE_IN_BYTES);

	/* write hash*/
	/* calculate hash and write to */
	if (CC_CommonCalcHash((uint8_t *)&gNAndNp, sizeof(gNAndNp), pHash, hashSize) != 0) {
		UTIL_LOG_ERR ("Common_CalcHashOnPubKey failed\n");
		goto END;
	}

	/* write hash*/
	status = 0;

	END:
	if (bn_n != NULL) {
		BN_free(bn_n);
	}
	return status;
}

/**
* @brief The CC_CommonCalcHBKFromFile reads RSA key from the file using passphrase
*        and returns its decrypted value.
*
* @param[in] pubKeyFileName_ptr - file name of the public key
* @param[out] pHash - hash output
* @param[in] hashSize - hash output size
*/
/*********************************************************/
int32_t CC_CommonCalcHBKFromFile(int8_t* pubKeyFileName_ptr, uint8_t *pHash, int32_t hashSize)
{

	int32_t status = -1;
	int32_t i;
	RSA *rsa_pkey = NULL;

	rsa_pkey = RSA_new();
	if (NULL == rsa_pkey) {
		UTIL_LOG_ERR("Failed RSA_new\n");
		goto END;
	}
	if (CC_CommonGetPubKey (&rsa_pkey, pubKeyFileName_ptr) != 0) {
		UTIL_LOG_ERR("Cannot read RSA public key\n");
		goto END;
	}

	/* get the modulus from BIGNUM to uint8_t* */
	BN_bn2bin(rsa_pkey->n, (uint8_t *)gN);
	UTIL_LOG_BYTE_BUFF("gN", gN, RSA_MOD_SIZE_IN_BYTES);

	/* calculate the Np, and get the output as BIGNUM*/
	if (CC_CommonRSACalculateNpInt(rsa_pkey->n, gNp, NP_BIN) != 0) {
		UTIL_LOG_ERR("Failed creating Np\n");
		goto END;
	}
	UTIL_LOG_BYTE_BUFF("gNp", gNp, NP_SIZE_IN_BYTES);

	/* copy the Np to the end of N and calc hash on both */
	memcpy(gNAndNp.pNBuff, gN, RSA_MOD_SIZE_IN_BYTES);
	memcpy(gNAndNp.pNpBuff, gNp, NP_SIZE_IN_BYTES);
	/* write hash*/

	/* calculate hash and write to */
	if (CC_CommonCalcHash((uint8_t *)&gNAndNp, RSA_MOD_SIZE_IN_BYTES+NP_SIZE_IN_BYTES, pHash, hashSize) != 0) {
		UTIL_LOG_ERR ("Common_CalcHashOnPubKey failed\n");
		goto END;
	}

	/* write hash*/
	status = 0;

	END:
	if (rsa_pkey != NULL) {
		RSA_free(rsa_pkey);
	}
	return status;
}

/**
 * @brief The function reads the pwd file name gets the pwd and returns it
 *
 * @param[in] pPwdFileName - file name of the password
 * @param[out] pwd - passphrase data
 *
 */
/*********************************************************/
int32_t CC_CommonGetPassphrase(int8_t *pPwdFileName, uint8_t **pwd)
{

	FILE *fp = NULL;
	int32_t fsize = 0;
	int32_t seek =0, i=0;
	int8_t *tmpBuf;
	int32_t status = 0;

	if (pPwdFileName == NULL) {
		UTIL_LOG_ERR("illegal file name\n");
		return -1;
	}

	if (pwd == NULL) {
		UTIL_LOG_ERR("illegal pwd\n");
		return -1;
	}

	fp = fopen (pPwdFileName, "r");
	if (fp == NULL) {
		UTIL_LOG_ERR ("Cannot open file %s\n", pPwdFileName);
		return -1;
	}


	/* Get the pwd file size */
	seek = fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (fsize == 0) {
		UTIL_LOG_ERR("PWD file is empty!\n");
		status = -1;
		goto END;
	}

	tmpBuf = (int8_t *)malloc(fsize+1);
	if (tmpBuf == NULL) {
		UTIL_LOG_ERR("failed to allocate memory\n");
		status = -1;
		goto END;
	}

	memset(tmpBuf, 0, fsize+1);
	/* get the file data */
	for (i=0; i<fsize; i++) {
		tmpBuf[i] = fgetc(fp);
		if (tmpBuf[i] == EOF || tmpBuf[i] == '\n') {
			tmpBuf[i] = '\0';
		}
	}
	*pwd = tmpBuf;
	status = 0;

	END:
	fclose(fp);
	return status;
}


