/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CCLIB

#include "ssi_regs.h"
#include "ssi_pal_memmap.h"
#include "ssi_hal.h"
#include "dx_sasi_kernel.h"
#include "ssi_pal_abort.h"

#include <hm_mman_ext.h>
#include <iomgr_ext.h>
#include <plat_cfg.h>
#include "tee_log.h"

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */
unsigned long gCcClockBase = 0;
#define CLOCK_ON_OFFSET  0x8C
#define CLOCK_OFF_OFFSET 0x88
#if 0
#define DX_BASE_CC         0x10210000 // size: 0x100000
#define DX_BASE_CC_SIZE    0x100000
#define DX_CLOCK_BASE      0x10001000
#define DX_CLOCK_BASE_SIZE 0x1000
#endif

/* *****************************************************************************
 *                GLOBALS
 * *************************************************************************** */

unsigned long gCcRegBase = 0;

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

/* !
 * HAL layer entry point.
 * Mappes ARM CryptoCell regisers to the HOST virtual address space.
 */
int SaSi_HalInit(void)
{
    void *r0 = NULL;

    void *r = hm_io_map(DX_BASE_CC, (void *)DX_BASE_CC, PROT_READ | PROT_WRITE);
    tlogd("hm_io_map:0x%x\n", ((unsigned int)(r)));
    if ((uintptr_t)r != DX_BASE_CC) {
        tloge("DX_HAL_Init hm map dx base 0x%x failed\n", (unsigned int)r);
        goto clean;
    }
    gCcRegBase = (unsigned long)DX_BASE_CC;

    r0 = hm_io_map(DX_CLOCK_BASE, (void *)DX_CLOCK_BASE, PROT_READ | PROT_WRITE);
    tlogd("hm_io_map:0x%x\n", ((unsigned int)(r0)));
    if ((uintptr_t)r0 != DX_CLOCK_BASE) {
        tloge("DX_HAL_Init hm map dx clock 0x%x failed\n", (unsigned int)r0);
        goto clean;
    }

    gCcClockBase                                                  = (unsigned long)DX_CLOCK_BASE;
    *((volatile unsigned long *)(gCcClockBase + CLOCK_ON_OFFSET)) = 0x18000000;
    asm volatile("dmb sy");

    return 0;

clean:
    tloge("DX_HAL_Init: hm_io_map failed\n");
    return -1;
}

/* !
 * HAL exit point.
 * Unmaps ARM CryptoCell registers.
 */
int SaSi_HalTerminate(void)
{
    int r      = hm_io_unmap(DX_BASE_CC, (void *)gCcRegBase);
    gCcRegBase = 0;
    return r;
}

/* !
 * Busy wait upon Interrupt Request Register (IRR) signals.
 * This function notifys for any ARM CryptoCell interrupt, it is the caller responsiblity
 * to verify and prompt the expected case interupt source.
 *
 * @param[in] data     - input data for future use
 * \return uint32_t The IRR value.
 */
uint32_t SaSi_HalWaitInterrupt(uint32_t data)
{
    uint32_t irr = 0;

    if (data == 0) {
        SaSi_PalAbort("SaSi_HalWaitInterrupt cant wait for nothing\n");
    }
    /* busy wait upon IRR signal */
    do {
        irr = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_IRR));
    } while (!(irr & data));

    /* clear interrupt */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_ICR),
                            data); // IRR and ICR bit map is the same use data to clear interrupt in ICR

    return irr;
}

/* !
 * Set HW cache parameters
 * This function need to be changed according to customer's platform
 *
 * \param void
 *
 * \return void
 */
void SaSi_HalInitHWCacheParams(void)
{
    /* AXIM_CACHE_PARAMS:
        This register overrides descriptor parameters for AXI
        transaction and also defines CACHE type of the transaction
        Bit[3:0] AWCACHE_LAST
        Bit[7:4] AWCACHE
        Bit[11:8] AWCACHE
        For coherency (ACP enabled) please write 0x277 */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, AXIM_CACHE_PARAMS), 0x277);
}

void DX_Clock_Init(void)
{
    *((volatile unsigned long *)(gCcClockBase + CLOCK_ON_OFFSET)) = 0x18000000;
    asm volatile("dmb sy");
}

void DX_Clock_Uninit(void)
{
    *((volatile unsigned long *)(gCcClockBase + CLOCK_OFF_OFFSET)) = 0x08000000;
    asm volatile("dmb sy");
}
