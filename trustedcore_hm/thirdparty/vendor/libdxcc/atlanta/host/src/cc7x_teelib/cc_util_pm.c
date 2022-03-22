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

#include "cc_hal.h"
#include "cc_regs.h"
#include "cc_util_pm.h"
#include "cc_fips.h"
#include "cc_plat.h"
#include "pki.h"
#include "cc_sram_map.h"
#include "cc_fips_defs.h"
#include "completion.h"

/******************************************************************************
*				PUBLIC FUNCTIONS
******************************************************************************/


void CC_UtilPmPowerDownDisable(void){

	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_POWER_DOWN_EN), POWER_DOWN_EN_OFF);

}


void CC_UtilPmPowerDownEnable(void){

	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_POWER_DOWN_EN), POWER_DOWN_EN_ON);
}


CCUtilError_t CC_UtilPmSuspend(void)
{
	return CC_UTIL_OK;
}


CCUtilError_t CC_UtilPmResume(void)
{
	CCUtilError_t  rc = 0;

#ifdef BIG__ENDIAN
	/* Set DMA endianess to big */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_ENDIAN) , 0xCCUL);
#else /* LITTLE__ENDIAN */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_ENDIAN) , 0x00UL);
#endif

	/* setting the hw cache parameters */
	CC_HalInitHWCacheParams();

	InitCompletion();

	/* clear TRNG source from SRAM */
	_ClearSram(CC_SRAM_RND_HW_DMA_ADDRESS, CC_SRAM_RND_MAX_SIZE);
	/* clear symmetric context from SRAM */
	_ClearSram(CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, CC_SRAM_DRIVER_ADAPTOR_CONTEXT_MAX_SIZE);
	/* clear PKA from SRAM */
	PkiClearAllPka();


	return rc;
}
