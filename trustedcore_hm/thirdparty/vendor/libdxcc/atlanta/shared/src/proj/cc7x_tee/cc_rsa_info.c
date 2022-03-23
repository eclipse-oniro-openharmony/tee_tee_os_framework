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

/* this file contains the definitions of the hashes used in the rsa */

#include "cc_rsa_local.h"
#include "cc_hash.h"
#include "cc_rsa_types.h"

const RsaHash_t RsaHashInfo_t[CC_RSA_HASH_NumOfModes] = {
        /*CC_RSA_HASH_MD5_mode          */        {CC_HASH_MD5_DIGEST_SIZE_IN_WORDS,CC_HASH_MD5_mode},
        /*CC_RSA_HASH_SHA1_mode         */        {CC_HASH_SHA1_DIGEST_SIZE_IN_WORDS, CC_HASH_SHA1_mode},
	/*CC_RSA_HASH_SHA224_mode       */	    {CC_HASH_SHA224_DIGEST_SIZE_IN_WORDS, CC_HASH_SHA224_mode},
	/*CC_RSA_HASH_SHA256_mode       */        {CC_HASH_SHA256_DIGEST_SIZE_IN_WORDS, CC_HASH_SHA256_mode},
	/*CC_RSA_HASH_SHA384_mode       */        {CC_HASH_SHA384_DIGEST_SIZE_IN_WORDS, CC_HASH_SHA384_mode},
	/*CC_RSA_HASH_SHA512_mode       */        {CC_HASH_SHA512_DIGEST_SIZE_IN_WORDS, CC_HASH_SHA512_mode},
	/*CC_RSA_After_MD5_mode         */        {CC_HASH_MD5_DIGEST_SIZE_IN_WORDS,CC_HASH_MD5_mode},
        /*CC_RSA_After_SHA1_mode        */        {CC_HASH_SHA1_DIGEST_SIZE_IN_WORDS, CC_HASH_SHA1_mode},
	/*CC_RSA_After_SHA224_mode      */        {CC_HASH_SHA224_DIGEST_SIZE_IN_WORDS, CC_HASH_SHA224_mode},
	/*CC_RSA_After_SHA256_mode      */        {CC_HASH_SHA256_DIGEST_SIZE_IN_WORDS, CC_HASH_SHA256_mode},
	/*CC_RSA_After_SHA384_mode      */        {CC_HASH_SHA384_DIGEST_SIZE_IN_WORDS, CC_HASH_SHA384_mode},
	/*CC_RSA_After_SHA512_mode      */        {CC_HASH_SHA512_DIGEST_SIZE_IN_WORDS, CC_HASH_SHA512_mode},
        /*CC_RSA_After_HASH_NOT_KNOWN_mode   */   {0,CC_HASH_NumOfModes},
        /*CC_RSA_HASH_NO_HASH_mode           */   {0,CC_HASH_NumOfModes},
};

const uint8_t RsaSupportedHashModes_t[CC_RSA_HASH_NumOfModes] = {
	/*CC_RSA_HASH_MD5_mode          */ CC_TRUE,
        /*CC_RSA_HASH_SHA1_mode         */ CC_TRUE,
        /*CC_RSA_HASH_SHA224_mode       */ CC_TRUE,
        /*CC_RSA_HASH_SHA256_mode       */ CC_TRUE,
        /*CC_RSA_HASH_SHA384_mode       */ CC_TRUE,
        /*CC_RSA_HASH_SHA512_mode       */ CC_TRUE,
        /*CC_RSA_After_MD5_mode         */ CC_TRUE,
        /*CC_RSA_After_SHA1_mode        */ CC_TRUE,
        /*CC_RSA_After_SHA224_mode      */ CC_TRUE,
        /*CC_RSA_After_SHA256_mode      */ CC_TRUE,
        /*CC_RSA_After_SHA384_mode      */ CC_TRUE,
        /*CC_RSA_After_SHA512_mode      */ CC_TRUE,
        /*CC_RSA_After_HASH_NOT_KNOWN_mode   */ CC_FALSE,
        /*CC_RSA_HASH_NO_HASH_mode           */ CC_FALSE,
};

