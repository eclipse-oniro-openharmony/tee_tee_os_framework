/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

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
