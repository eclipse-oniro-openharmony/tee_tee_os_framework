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

#ifndef _NVM_MNG_H
#define _NVM_MNG_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief The NVM_ReadAESKey function is a NVM interface function -
 *        The function retrieves the AES CTR 128 bit key from the NVM
 *
 *
 * @param[out] AESKey   -  Kce from OTP for SW image decryption
 *
 * @return DxError_t - On success the value DX_OK is returned, and on failure   -a value from NVM_error.h
 */
DxError_t NVM_ReadAESKey(AES_Key_t AESKey);

#ifdef __cplusplus
}
#endif

#endif
