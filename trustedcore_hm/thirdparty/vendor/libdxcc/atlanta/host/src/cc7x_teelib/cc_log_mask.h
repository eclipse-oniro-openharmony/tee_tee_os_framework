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

#ifndef _CC_LOG_MASK_H_
#define _CC_LOG_MASK_H_

/* CCLIB4 specific component masks */
#define CC_LOG_MASK_CCLIB    				(1)
#define CC_LOG_MASK_CC_API				(1<<1)
#define CC_LOG_MASK_CC_SYM_DRIVER			(1<<2)
#define CC_LOG_MASK_MLLI				(1<<3)
#define CC_LOG_MASK_HW_QUEUE				(1<<4)
#define CC_LOG_MASK_COMPLETION				(1<<5)
#define CC_LOG_MASK_INFRA				(1<<6)
#define CC_LOG_MASK_LLF				(1<<13)
#define CC_LOG_MASK_ASYM_ECC				(1<<14)
#define CC_LOG_MASK_ASYM_RSA_DH				(1<<15)
#define CC_LOG_MASK_ASYM_KDF				(1<<16)
#define CC_LOG_MASK_ASYM_LLF				(1<<17)
#define CC_LOG_MASK_ASYM_RND				(1<<18)
#define CC_LOG_MASK_UTILS				(1<<19)


#define CC_LOG_MASK_ASYM_ALL \
          (CC_LOG_MASK_ASYM_ECC || CC_LOG_MASK_ASYM_RSA_DH || \
           CC_LOG_MASK_ASYM_KDF || CC_LOG_MASK_ASYM_LLF || CC_LOG_MASK_ASYM_RND)

#endif /*_CC_LOG_MASK_H_*/

