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

/*!
@file
@brief This file contains all of the enums and definitions that are used for the
        CryptoCell HW Key APIs, as well as the APIs themselves.
*/

#ifndef __CC_UTIL_HW_KEY_H__
#define __CC_UTIL_HW_KEY_H__

#include "cc_pal_types.h"

typedef enum {
	CC_HW_KEY_SLOT_0 = 0,
	CC_HW_KEY_SLOT_1 = 1,
	CC_HW_KEY_SLOT_2 = 2,
	CC_HW_KEY_SLOT_3 = 3,
	CC_HW_KEY_SLOT_RESERVE32B = 0x7FFFFFFFL
} CCUtilSlotNum_t;

typedef enum {
	CC_HW_KEY_RET_OK = 0,
	CC_HW_KEY_RET_NULL_KEY_PTR,	/* Invalid key */
	CC_HW_KEY_RET_BAD_KEY_SIZE,	/* Invalid key size */
	CC_HW_KEY_RET_BAD_SLOT_NUM,	/* Invalid slot number */
	CC_HW_KEY_RET_RESERVE32B = 0x7FFFFFFFL
} CCUtilHwKeyRetCode_t;


/*!
@brief This function Sets key into HW key slot.
\note It overrides any previous existing data in the HW slot. It is the user responsibility to manage the keys in the HW slots.
@return CC_HW_KEY_RET_OK on success.
@return A non-zero value in case of failure.
*/
CCUtilHwKeyRetCode_t CC_UtilHwKeySet(uint8_t *pKey,           /*!< [in] Pointer to the key buffer */
				     size_t keySize,          /*!< [in] Key size in bytes */
				     CCUtilSlotNum_t slotNum  /*!< [in] Slot number for setting the key in it */);


#endif /*__CC_UTIL_HW_KEY_H__*/

