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

#ifndef  _OEM_ASSET_UTILS_H
#define  _OEM_ASSET_UTILS_H


#define RSA_OAEP_KEY_SIZE_IN_BITS 2048UL
#define RSA_OAEP_KEY_SIZE_IN_BYTES (RSA_OAEP_KEY_SIZE_IN_BITS/8)
#define  OEM_GEN_CSR_TOKEN         0x43535252
#define  CM_GEN_OEM_KEY_TOKEN      0x43535241

/* oem key definitions */
typedef struct {
        unsigned int      token;
        unsigned int      version;
        unsigned int      len;
        unsigned char     oemKeyRsaEnc[RSA_OAEP_KEY_SIZE_IN_BYTES];
} EncOemKeyBuff_t;

#define ENC_OEM_KEY_BUFF_SIZE 268 //sizeof(EncOemKeyBuff_t)


/* csr  definition */
/* oem key definitions */
typedef struct {
        unsigned int      token;
        unsigned int      version;
        unsigned int      len;
        unsigned char     pubKey0[RSA_OAEP_KEY_SIZE_IN_BYTES];
        unsigned char     csrSign[RSA_OAEP_KEY_SIZE_IN_BYTES];
} CsrBuff_t;

#endif /*_OEM_ASSET_UTILS_H*/
