/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef _COMMON_RSA_KEYPAIR_UTIL_H
#define _COMMON_RSA_KEYPAIR_UTIL_H

#include <stdint.h>

#include "common_rsa_keypair.h"

typedef struct {
    uint8_t pNBuff[RSA_MOD_SIZE_IN_BYTES];
    uint8_t pNpBuff[NP_SIZE_IN_BYTES];
} DxRsaKeyNandNp_t;

/*
 * @brief The function reads RSA key from the file and returns its N and Np.
 *
 * @param[in] PemEncryptedFileName_ptr - file name of the key pair
 * @param[in] pwdFileName - file name of the password
 * @param[out] pNbuff - N  buffer
 * @param[in/out] pNbuffSize - as input - max size of pNbuff
 *                              as output - actual size of pNbuff
 */
/* ****************************************************** */
int DX_Common_GetNbuffFromKeyPair(char *PemEncryptedFileName_ptr, char *pwdFileName, unsigned char *pNbuff,
                                  unsigned int *pNbuffSize);

/*
 * @brief The function reads RSA key from the file and returns its N and Np.
 *
 * @param[in] PemEncryptedFileName_ptr - file name of the key pair
 * @param[in] pwdFileName - file name of the password
 * @param[out] pNAndNp - N and Np buffer
 * @param[in/out] pNAndNpSize - as input - max size of pNAndNp
 *                              as output - actual size of pNAndNp
 */
/* ****************************************************** */
int DX_Common_GetNAndNpFromKeyPair(char *PemEncryptedFileName_ptr, char *pwdFileName, unsigned char *pNAndNp,
                                   unsigned int *pNAndNpSize);

/*
 * @brief The function reads RSA key from the file and returns its N and Np.
 *
 * @param[in] pubKeyFileName_ptr - file name of the key pair
 * @param[out] pNAndNp - N and Np buffer
 * @param[in/out] pNAndNpSize - as input - max size of pNAndNp
 *                              as output - actual size of pNAndNp
 */
/* ****************************************************** */
int DX_Common_GetNAndNpFromPubKey(char *pubKeyFileName_ptr, unsigned char *pNAndNp, unsigned int *pNAndNpSize);

/*
 * @brief The function reads the pwd file name gets the pwd and returns it
 *
 * @param[in] pPwdFileName - file name of the password
 * @param[out] pwd - passphrase data
 *
 */
/* ****************************************************** */
int DX_Common_GetPassphrase(char *pPwdFileName, unsigned char **pwd);

#endif
