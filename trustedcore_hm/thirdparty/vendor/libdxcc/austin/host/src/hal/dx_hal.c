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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CCLIB

#include "tee_log.h"
#include "dx_cc_regs.h"
#include "dx_pal_memmap.h"
#include "dx_hal.h"
#include "dx_crys_kernel.h"
#include "dx_pal_abort.h"
#include "dx_otp_defs.h"
#include "dx_cclib.h"
#include "sbrt_management_hw_defs.h"

#include <hm_mman_ext.h>
#include <iomgr_ext.h>
#include <plat_cfg.h>

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */
#define DX_CC_REG_AREA_LEN 0x1000

/* *****************************************************************************
 *                GLOBALS
 * *************************************************************************** */

unsigned long gCcRegBase = 0;

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */
/* !
 * HAL layer entry point.
 * Mappes CryptoCell 4.X regisers to the HOST virtual address space.
 */
int DX_HAL_Init(void)
{
    void *r = hm_io_map(DX_BASE_CC, NULL, PROT_READ | PROT_WRITE);
    if (r != (void *)-1) {
        gCcRegBase = (unsigned long)r;
        return 0;
    }

    tloge("DX_HAL_Init: hm_io_map failed\n");
    return -1;
}

/* !
 * HAL exit point.
 * Unmaps CryptoCell 4.X registers.
 */
int DX_HAL_Terminate(void)
{
    int r      = hm_io_unmap(DX_BASE_CC, (void *)gCcRegBase);
    gCcRegBase = 0;
    return r;
}

/* !
 * Busy wait upon Interrupt Request Register (IRR) signals.
 * This function notifys for any CC interrupt, it is the caller responsiblity
 * to verify and prompt the expected case interupt source.
 *
 * @param[in] data     - input data for future use
 * \return uint32_t The IRR value.
 */
uint32_t DX_HAL_WaitInterrupt(uint32_t data)
{
    uint32_t irr = 0;

    if (data == 0) {
        DX_PAL_Abort("DX_HAL_WaitInterrupt cant wait for nothing\n");
    }
    /* busy wait upon IRR signal */
    do {
        irr = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_IRR));
    } while (!(irr & data));

    /* clear interrupt */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_ICR),
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
void DX_HAL_InitHWCacheParams(void)
{
    /* AXIM_CACHE_PARAMS:
        This register overrides descriptor parameters for AXI
        transaction and also defines CACHE type of the transaction
        Bit[3:0] AWCACHE_LAST
        Bit[7:4] AWCACHE
        Bit[11:8] AWCACHE
        For coherency (ACP enabled) please write 0x277
        f00291367 change to SCCC cache coherency mode from HCCC mode */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, AXIM_CACHE_PARAMS), 0x333);
}

/* !
 * @brief This function retrives a 32bit word from the OTP memory.
 * @param[in] otpAddress    - Address in OTP [in Words]
 * @param[out] otpWord        - the returned OTP word
 *
 * @return DxError_t         - On success: the value DX_SUCCESS is returned,
 *                       On failure: a value from sbrom_management_error.h
 */
DxError_t DX_HAL_ReadOTPWord(uint32_t otpAddress, uint32_t *otpWord)
{
    uint32_t regVal = 0;

    /* Check input variables */
    if (otpWord == DX_NULL) {
        return DX_HAL_EINVAL;
    }

    if (otpAddress > DX_OTP_LAST_OFFSET) {
        return DX_HAL_EINVAL;
    }

    /* Change OTP address to be in bytes */
    otpAddress *= sizeof(uint32_t);

    /* Verify that the HW finished initialization */
    DX_CCLIB_WAIT_ON_LCS_VALID_BIT();

    /* Fetch the word */
    DX_SBRT_READ_WORD_VIA_AIB(DX_SBRT_NVM_READ_ADDR | otpAddress, regVal);

    *otpWord = regVal;

    return DX_HAL_OK;
}
/* !
 * @brief This function receives a 32-bit word, and burn it to the OTP memory.
 *      Note:
 *      The customer should develop the required implementation for programming the OTP bit-by-bit (no more than once).
 *
 * @param[in] otpAddress    - Address in OTP [in Words]
 * @param[in] otpWord        - OTP 32bit word
 *
 * @return DxError_t         - On success: the value DX_SUCCESS is returned,
 *                       On failure: a value from sbrom_management_error.h
 */
DxError_t DX_HAL_WriteOTPWord(uint32_t otpAddress, uint32_t otpWord)
{
    uint32_t otpVal;

    /* Check input variables */
    if (otpAddress > DX_OTP_LAST_OFFSET) {
        return DX_HAL_EINVAL;
    }

    /* Change OTP address to be in bytes */
    otpAddress *= sizeof(uint32_t);

    /* Read and Modify */
    DX_SBRT_READ_WORD_VIA_AIB(DX_SBRT_NVM_READ_ADDR | otpAddress, otpVal);
    otpWord |= otpVal;

    /* Verify that the HW finished initialization */
    DX_CCLIB_WAIT_ON_LCS_VALID_BIT();

    /* Write the word */
    DX_SBRT_WRITE_WORD_VIA_AIB(DX_SBRT_NVM_WRITE_ADDR | otpAddress, otpWord);

    /* Read the word to verify operation status */
    DX_SBRT_READ_WORD_VIA_AIB(DX_SBRT_NVM_READ_ADDR | otpAddress, otpVal);

    if (otpVal != otpWord) {
        return DX_HAL_WRONG_OTP;
    }

    return DX_HAL_OK;
}
