/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

/* ************ Include Files ************** */
// #include <unistd.h>
// #include <sys/mman.h>
// #include <fcntl.h>
#include "dx_pal_types.h"
#include "dx_host.h"
#include "dx_bitops.h"
#include "dx_cc_regs.h"
#include "sep_ctx.h"
#include "hm_mman_ext.h"

/* *********************** Defines **************************** */

static int halMapSignal = -1;
/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Private Functions **************************** */

/* *********************** Public Functions **************************** */

/*
 * @brief This function purpose is to return the base virtual address that maps the
 *        base physical address
 *
 * @param[in] physicalAddress - Starts physical address of the I/O range to be mapped.
 * @param[in] mapSize - Number of bytes that were mapped
 * @param[out] ppVirtBuffAddr - Pointer to the base virtual address to which the physical pages were mapped
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t DX_PAL_MemMap(uint32_t physicalAddress, uint32_t mapSize, uint32_t **ppVirtBuffAddr)
{
    if (halMapSignal >= 0) { /* already opened */
        return 0;
    }
    int prot = PROT_READ | PROT_WRITE | PROT_nGnRnE;

    prot |= PROT_nGnRnE;
    *ppVirtBuffAddr = (uint32_t *)hm_mmap_physical(*ppVirtBuffAddr, mapSize, prot, physicalAddress);

    if ((*ppVirtBuffAddr == NULL) || (*ppVirtBuffAddr == MAP_FAILED)) {
        halMapSignal = -1;
        return 2;
    } else {
        halMapSignal = 1;
    }

    return 0;
} /* End of DX_PAL_MemMap */

/*
 * @brief This function purpose is to Unmaps a specified address range previously mapped
 *        by DX_PAL_MemMap
 *
 *
 * @param[in] pVirtBuffAddr - Pointer to the base virtual address to which the physical
 *            pages were mapped
 * @param[in] mapSize - Number of bytes that were mapped
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t DX_PAL_MemUnMap(uint32_t *pVirtBuffAddr, uint32_t mapSize)
{
    if (halMapSignal < 0) {
        return 1;
    }

    (void)munmap(pVirtBuffAddr, mapSize);
    halMapSignal = -1;
    return 0;
} /* End of DX_PAL_MemUnMap */
