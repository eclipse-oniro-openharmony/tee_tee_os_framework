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

#ifndef _OEM_ASSET_UTILS_H
#define _OEM_ASSET_UTILS_H

#define RSA_OAEP_KEY_SIZE_IN_BITS  2048UL
#define RSA_OAEP_KEY_SIZE_IN_BYTES (RSA_OAEP_KEY_SIZE_IN_BITS / 8)
#define OEM_GEN_CSR_TOKEN          0x43535252
#define CM_GEN_OEM_KEY_TOKEN       0x43535241

/* oem key definitions */
typedef struct {
    unsigned int token;
    unsigned int version;
    unsigned int len;
    unsigned char oemKeyRsaEnc[RSA_OAEP_KEY_SIZE_IN_BYTES];
} EncOemKeyBuff_t;

#define ENC_OEM_KEY_BUFF_SIZE 268 // sizeof(EncOemKeyBuff_t)

/* csr  definition */
/* oem key definitions */
typedef struct {
    unsigned int token;
    unsigned int version;
    unsigned int len;
    unsigned char pubKey0[RSA_OAEP_KEY_SIZE_IN_BYTES];
    unsigned char csrSign[RSA_OAEP_KEY_SIZE_IN_BYTES];
} CsrBuff_t;

#endif /* _OEM_ASSET_UTILS_H */
