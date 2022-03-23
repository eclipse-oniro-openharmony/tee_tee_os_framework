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

#ifndef  _HMAC_DEFS_H__
#define  _HMAC_DEFS_H__

/* this files provides definitions required for HMAC engine drivers */
#define HMAC_DECRYPTED_OPAD_CONST_BLOCK 0x601D1102, 0xAD34E4AA, 0xB9351FAA, 0xD7356DF1
#define HMAC_DECRYPTED_IPAD_CONST_BLOCK 0xA8473C7E, 0x2AE67627, 0x50ADFC61, 0xEE6F3117

#define AES_CTR_NO_COUNTER_INC_REG_ADDR	0x4D8

#endif /*_HMAC_DEFS_H__*/

