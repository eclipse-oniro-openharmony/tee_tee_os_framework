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

static int halFileH = -1;
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
uint32_t SaSi_PalMemMap(uint32_t physicalAddress, uint32_t mapSize, uint32_t **ppVirtBuffAddr)
{
    /* Open device file if not already opened */
    if (halFileH >= 0) { /* already opened */
        return 0;
    }

    halFileH = open("/dev/mem", O_RDWR | O_SYNC);
    if (halFileH < 0) {
        return 1;
    }
    (void)fcntl(halFileH, F_SETFD, FD_CLOEXEC);

    *ppVirtBuffAddr = (uint32_t *)mmap(0, mapSize, PROT_READ | PROT_WRITE, MAP_SHARED, halFileH, physicalAddress);
    if ((*ppVirtBuffAddr == NULL) || (*ppVirtBuffAddr == MAP_FAILED)) {
        close(halFileH);
        halFileH = -1;
        return 2;
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
    if (halFileH < 0) {
        return 1;
    }

    munmap(pVirtBuffAddr, mapSize);
    close(halFileH);
    halFileH = -1;
    return 0;
} /* End of SaSi_PalMemUnMap */
