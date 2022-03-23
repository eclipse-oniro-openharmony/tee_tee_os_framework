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

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CCLIB

#include "tee_log.h"
#include "cc_regs.h"
#include "cc_pal_memmap.h"
#include "cc_hal.h"
#include "dx_crys_kernel.h"
#include "cc_pal_abort.h"

#include <hm_mman_ext.h>
#include <iomgr_ext.h>
#include <plat_cfg.h>



/******************************************************************************
*				DEFINITIONS
******************************************************************************/
#define DX_CC_REG_AREA_LEN 0x100000

/******************************************************************************
*				GLOBALS
******************************************************************************/

unsigned long gCcRegBase = 0;

/******************************************************************************
*				FUNCTIONS
******************************************************************************/

/*!
 * HAL layer entry point.
 * Mappes ARM CryptoCell regisers to the HOST virtual address space.
 */
int CC_HalInit(void)
{
	void *r = hm_io_map(DX_BASE_CC, (void *)DX_BASE_CC, PROT_READ | PROT_WRITE);
	if (r != (void *) -1) {
		gCcRegBase = (unsigned long)DX_BASE_CC;
		return 0;
	}

	tloge("CC_HalInit: hm_io_map failed\n");
	return -1;
}


/*!
 * HAL exit point.
 * Unmaps ARM CryptoCell registers.
 */
int CC_HalTerminate(void)
{
	int r = hm_io_unmap(DX_BASE_CC, (void *)gCcRegBase);
	gCcRegBase = 0;
	return r;
}


/*!
 * Busy wait upon Interrupt Request Register (IRR) signals.
 * This function notifys for any ARM CryptoCell interrupt, it is the caller responsiblity
 * to verify and prompt the expected case interupt source.
 *
 * @param[in] data 	- input data for future use
 * \return uint32_t The IRR value.
 */
uint32_t CC_HalWaitInterrupt(uint32_t data)
{
	uint32_t irr = 0;

    if (0 == data) {
            CC_PalAbort("CC_HalWaitInterrupt cant wait for nothing\n");
    }
	/* busy wait upon IRR signal */
    do {
            irr = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_IRR));
    } while (!(irr & data));

	/* clear interrupt */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_ICR), data); // IRR and ICR bit map is the same use data to clear interrupt in ICR

	return irr;
}


void CC_HalClearInterrupt(uint32_t data)
{
	if (0 == data) {
		CC_PalAbort("CC_HalClearInterrupt illegal input\n");
	}

	/* clear interrupt */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_ICR), data);

	return;
}

/*!
 * Set HW cache parameters
 * This function need to be changed according to customer's platform
 *
 * \param void
 *
 * \return void
 */
void CC_HalInitHWCacheParams(void)
{

	/* AXIM_CACHE_PARAMS:
		This register overrides descriptor parameters for AXI
		transaction and also defines CACHE type of the transaction
		Bit[3:0] AWCACHE_LAST
		Bit[7:4] AWCACHE
		Bit[11:8] AWCACHE
		For coherency (ACP enabled) please write 0x277 */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(CRY_KERNEL, AXIM_CACHE_PARAMS), 0x277);

}






