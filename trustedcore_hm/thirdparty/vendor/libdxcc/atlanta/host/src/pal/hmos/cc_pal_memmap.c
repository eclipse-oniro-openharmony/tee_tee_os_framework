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



/************* Include Files ****************/
//#include <unistd.h>
//#include <sys/mman.h>
//#include <fcntl.h>
#include <stdint.h>
#include "cc_pal_types.h"
#include "cc_pal_memmap.h"
#include "dx_host.h"

/************************ Defines ******************************/
#define MAP_FAILED      ((void *) -1)
#define PROT_READ       0x01    /* pages can be read */
#define PROT_WRITE      0x02    /* pages can be written */
#define PROT_nGnRnE     0x20    /* Device-nGnRnE */

/************************ Enums ******************************/

/************************ Typedefs ******************************/

/************************ Global Data ******************************/

/************************ Private Functions ******************************/

/************************ Public Functions ******************************/
void *hm_mmap_physical(void *vaddr, size_t length, int prot, uint64_t paddr);
int munmap(void *addr, size_t length);

/**
 * @brief This function purpose is to return the base virtual address that maps the
 *        base physical address
 *
 * @param[in] physicalAddress - Starts physical address of the I/O range to be mapped.
 * @param[in] mapSize - Number of bytes that were mapped
 * @param[out] ppVirtBuffAddr - Pointer to the base virtual address to which the physical pages were mapped
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t CC_PalMemMap(CCDmaAddr_t physicalAddress,
	               uint32_t mapSize,
		       uint32_t **ppVirtBuffAddr)
{
	*ppVirtBuffAddr = (uint32_t *)hm_mmap_physical(
				*ppVirtBuffAddr,
				mapSize,
				PROT_READ | PROT_WRITE | PROT_nGnRnE,
				physicalAddress);
	if ((*ppVirtBuffAddr == NULL) || (*ppVirtBuffAddr == MAP_FAILED)) {
		return -1;
	}
	return 0;
}/* End of CC_PalMemMap */


/**
 * @brief This function purpose is to Unmaps a specified address range previously mapped
 *        by CC_PalMemMap
 *
 *
 * @param[in] pVirtBuffAddr - Pointer to the base virtual address to which the physical
 *            pages were mapped
 * @param[in] mapSize - Number of bytes that were mapped
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t CC_PalMemUnMap(uint32_t *pVirtBuffAddr,
	                 uint32_t mapSize)
{
	munmap(pVirtBuffAddr, mapSize);
	return 0;
}/* End of CC_PalMemUnMap */
