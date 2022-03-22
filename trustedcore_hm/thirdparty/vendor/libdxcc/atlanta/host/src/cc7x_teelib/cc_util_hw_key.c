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

#include "cc_util_hw_key.h"
#include "cc_hal.h"
#include "cc_regs.h"
#include "cc_fips_defs.h"
#include "cc_pal_mem.h"

/* HW KFDE key is 256b */
#define CC_KFDE_SIZE_WORDS 8
#define CC_KFDE_SIZE_BYTES (CC_KFDE_SIZE_WORDS<<2)

CCUtilHwKeyRetCode_t CC_UtilHwKeySet(uint8_t *pKey,
				     size_t keySize,
				     CCUtilSlotNum_t slotNum)
{
	uint32_t kfde[CC_KFDE_SIZE_WORDS] = {0};
	int i;
	uint32_t reg_offset;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	if (pKey == NULL) {
		return CC_HW_KEY_RET_NULL_KEY_PTR;
	}

	if (keySize > CC_KFDE_SIZE_BYTES) {
		return CC_HW_KEY_RET_BAD_KEY_SIZE;
	}

	switch (slotNum) {
	case CC_HW_KEY_SLOT_0:
		reg_offset = CC_REG_OFFSET(HOST_RGF, HOST_KFDE0);
		break;
	case CC_HW_KEY_SLOT_1:
		reg_offset = CC_REG_OFFSET(HOST_RGF, HOST_KFDE1);
		break;
	case CC_HW_KEY_SLOT_2:
		reg_offset = CC_REG_OFFSET(HOST_RGF, HOST_KFDE2);
		break;
	case CC_HW_KEY_SLOT_3:
		reg_offset = CC_REG_OFFSET(HOST_RGF, HOST_KFDE3);
		break;
	default:
		return CC_HW_KEY_RET_BAD_SLOT_NUM;
	}

	CC_PalMemCopy((uint8_t*)kfde, pKey, keySize);

	for (i = 0; i < CC_KFDE_SIZE_WORDS; ++i) {
		CC_HAL_WRITE_REGISTER(reg_offset, kfde[i]);
	}

	return CC_HW_KEY_RET_OK;
}

