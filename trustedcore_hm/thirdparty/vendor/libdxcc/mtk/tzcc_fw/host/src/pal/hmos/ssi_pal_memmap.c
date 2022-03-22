/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "ssi_pal_types.h"
#include "dx_host.h"

/* *********************** Defines **************************** */
#define MAP_FAILED  ((void *)-1)
#define PROT_READ   0x01 /* pages can be read */
#define PROT_WRITE  0x02 /* pages can be written */
#define PROT_nGnRnE 0x20 /* Device-nGnRnE */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Private Functions **************************** */

/* *********************** Public Functions **************************** */
void *hm_mmap_physical(void *vaddr, size_t length, int prot, uint64_t paddr);
int munmap(const void *addr, size_t length);

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
uint32_t SaSi_PalMemMap(uint32_t physicalAddress, uint32_t mapSize, uint32_t **ppVirtBuffAddr)
{
    *ppVirtBuffAddr =
        (uint32_t *)hm_mmap_physical(*ppVirtBuffAddr, mapSize, PROT_READ | PROT_WRITE | PROT_nGnRnE, physicalAddress);
    if ((*ppVirtBuffAddr == NULL) || (*ppVirtBuffAddr == MAP_FAILED)) {
        return -1;
    }
    return 0;
} /* End of SaSi_PalMemMap */

/*
 * @brief This function purpose is to Unmaps a specified address range previously mapped
 *        by SaSi_PalMemMap
 *
 *
 * @param[in] pVirtBuffAddr - Pointer to the base virtual address to which the physical
 *            pages were mapped
 * @param[in] mapSize - Number of bytes that were mapped
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t SaSi_PalMemUnMap(uint32_t *pVirtBuffAddr, uint32_t mapSize)
{
    munmap(pVirtBuffAddr, mapSize);
    return 0;
} /* End of SaSi_PalMemUnMap */
