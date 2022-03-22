/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

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
int32_t SaSi_CommonGetNbuffFromKeyPair(int8_t *PemEncryptedFileName_ptr, int8_t *pwdFileName, uint8_t *pNbuff,
                                       uint32_t *pNbuffSize);

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
int32_t SaSi_CommonGetNAndNpFromKeyPair(int8_t *PemEncryptedFileName_ptr, int8_t *pwdFileName, uint8_t *pNAndNp,
                                        uint32_t *pNAndNpSize);

/*
 * @brief The function reads RSA key from the file and returns its N and Np.
 *
 * @param[in] pubKeyFileName_ptr - file name of the key pair
 * @param[out] pNAndNp - N and Np buffer
 * @param[in/out] pNAndNpSize - as input - max size of pNAndNp
 *                              as output - actual size of pNAndNp
 */
/* ****************************************************** */
int32_t SaSi_CommonGetNAndNpFromPubKey(int8_t *pubKeyFileName_ptr, uint8_t *pNAndNp, uint32_t *pNAndNpSize);

/*
 * @brief The function reads the pwd file name gets the pwd and returns it
 *
 * @param[in] pPwdFileName - file name of the password
 * @param[out] pwd - passphrase data
 *
 */
/* ****************************************************** */
int32_t SaSi_CommonGetPassphrase(int8_t *pPwdFileName, uint8_t **pwd);

#endif
