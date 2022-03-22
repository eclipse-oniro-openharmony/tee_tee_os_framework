/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "ssi_pal_mem.h"
#include "ssi_pal_types.h"
#include "ssi_hal_plat.h"
#include "ssi_sram_map.h"
#include "dx_sasi_kernel.h"
#include "ssi_regs.h"
#include "pka_hw_defs.h"
#include "pka_export.h"
#include "pka.h"
#include "pka_ut.h"
#include "pka_error.h"

extern SaSi_PalMutex sasiAsymCryptoMutex;
/* *********************** Defines **************************** */

/* Maximum allowed PKA registers are 32 (PKA_MAX_COUNT_OF_PHYS_MEM_REGS): first 2 (PKA_REG_N & PKA_REG_NP) servers for N
   (modulus) and Np respectivly. last 2 (PKA_REG_T0 & PKA_REG_T1) are reserved for HW use. so we have total of 28
   registers for SW usage list of maximum 28 allowed temp PKA registers for functions.
   Note: last 2 are numbered 0xFF - for debug goals */
const int8_t regTemps[PKA_MAX_COUNT_OF_PHYS_MEM_REGS] = {
    PKA_REG_N, PKA_REG_NP, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,       0x09,      0x0A,
    0x0B,      0x0C,       0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,       0x14,      0x15,
    0x16,      0x17,       0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, PKA_REG_T0, PKA_REG_T1
};
/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

#if defined PKA_DEBUG && defined DEBUG
uint32_t tempRes[PKA_MAX_REGISTER_SIZE_IN_32BIT_WORDS];
uint32_t tempRes1[PKA_MAX_REGISTER_SIZE_IN_32BIT_WORDS];
#endif

/* *********************** Public Functions **************************** */

/* ********************************************************************* */
/* *********       PKA initialisation functions and macros      ******** */
/* ********************************************************************* */

/* **********        PKA_ModDivideBy2            ******************** */
/*
 * @brief This function performs modular division by 2: rRes = rX / 2 mod rN.
 *
 *
 * @param[in] LenId  - ID of entry of regsSizesTable containing rX modulus exact length.
 * @param[in] rX     - Virtual pointer to PKA register X.
 * @param[out] rN    - Virtual pointer to PKA register, containing the modulus N.
 * @param[out] rRes  - Virtual pointer to PKA register, containing the result.
 * @param[in] Tag    - The user defined value (Tag <= 31), used for indication goals.
 *
 * @return - no return parameters.
 *
 */
void PKA_ModDivideBy2(uint32_t LenID, uint32_t rX, uint32_t rN, uint32_t rRes, uint32_t Tag)
{
    /* DECLARATIONS */

    uint32_t bitVal = 0;

    /* FUNCTION LOGIC */
    Tag = Tag;
    if (rX != rRes) {
        PKA_COPY(LEN_ID_MAX_BITS, rRes /* dst */, rX /* src */);
    }

    /* if the vector rX is odd, then add the modulus and then  divide by 2 */

    PKA_READ_BIT0(LenID + 1, rRes /* regNum */, bitVal);
    if (bitVal == 1) {
        PKA_ADD(LenID + 1, rRes /* Res */, rRes /* P */, rN /* OpB=N=0 */);
    }

    /* divide by 2 */
    PKA_SHR_FILL0(LenID + 1, rRes /* Res */, rRes /* P */, 1 - 1 /* S */);

} /* END OF function PKA_ModDivideBy2 */

/* **********   PKA_GetRegEffectiveSizeInBits  ******************** */
/*
 * @brief This function returns effective size in bits of data placed in PKA register.
 *
 *
 * @param[in] reg    - Virtual pointer to PKA register.
 *
 * @return - effective size of data in register (bits).
 *
 */
uint32_t PKA_GetRegEffectiveSizeInBits(uint32_t reg /* in */)
{
    /* DECLARATIONS */

    // RL Do resistant and add flag to arg.

    int size = 1, i;
    uint32_t addr;
    uint32_t currWord = 0, mask = 1Ul << 31;

    /* FUNCTION LOGIC */

    /* read register address and full operation size in bits */
    PKA_GetRegAddress(reg, addr);
    PKA_ReadRegSize(size, LEN_ID_MAX_BITS /* lenID */);

    /* register size in words */
    size = CALC_FULL_32BIT_WORDS(size);

    /* read words and find MSWord */
    for (i = size - 1; i >= 0; i--) {
        PKA_HW_READ_VALUE_FROM_PKA_MEM(addr + i, currWord);
        if (currWord != 0)
            break;
    }

    size = SASI_BITS_IN_32BIT_WORD * (i + 1); // in bits

    if (currWord == 0)
        return size;

    /* find number of bits in the MS word */
    for (i = 1; i <= SASI_BITS_IN_32BIT_WORD; i++) {
        if (currWord & mask)
            break;
        size--;
        mask >>= 1;
    }

    return size;

} /* END OF function PKA_GetRegEffectiveSizeInBits */

/*
 * The function returns MS-bit from register r.
 *
 *
 * @author reuvenl (6/12/2014)
 *
 * @param rX  - register virt. pointer.
 * @param i  - index of the requirred bit.
 * @param pW - pointer to 32-bit current word, which must be saved by
 *         caller through reading bits from the register.
 * @param pIsNew -  pointer to indicator is this a new start (pIsNew=1) of
 *             the function for this register. The value is updated
 *             to 0 by the function after first start.
 *
 * @return uint32_t - bit's value
 */
uint32_t pka_getNextMsBit(uint32_t rX, int32_t i, uint32_t *pW, uint32_t *pIsNew)
{
    uint32_t b;

    if (*pIsNew || (i & 31UL) == 31) {
        PKA_READ_WORD_FROM_REG(*pW, i >> 5, rX);
        /* ones only */
        if ((i & 31UL) != 31)
            *pW <<= (31 - (i & 31UL));
        *pIsNew = 0;
    }

    b = *pW >> 31;
    *pW <<= 1;

    return b;
}

/*
 * The function returns 2 MS-bits from register r.
 *
 * @author reuvenl (6/12/2014)
 *
 * @param rX  - register virt. pointer.
 * @param i  - index of the requirred bit.
 * @param pW - pointer to 32-bit current word, which must be saved by
 *         caller through reading bits from the register.
 * @param pIsNew -   pointer to indicator is it a new start of
 *             the function for this register or not. The value is updated
 *             to FALSE by the function after start.
 *
 * @return uint32_t - bit's value
 */
uint32_t pka_get2msbits(uint32_t rX, int32_t i, uint32_t *pW, uint32_t *pIsNew)
{
    uint32_t b;

    ASSERT(!(i & 1));

    if (*pIsNew || (i & 0x1F) == 30) {
        PKA_READ_WORD_FROM_REG(*pW, i >> 5, rX);
        *pIsNew = 0;
    }

    b = (*pW >> (i & 0x1F)) & 0x3;

    return b;
}

void PKA_SetLenIds(uint32_t sizeInBits, uint32_t lenId)
{
    PKA_SetRegSize(sizeInBits, lenId);
    PKA_SetRegSize(GET_FULL_OP_SIZE_BITS(sizeInBits), lenId + 1);
}

SaSiError_t PKA_InitAndMutexLock(uint32_t sizeInBits, uint32_t *pkaRegCount)
{
    SaSiError_t err = SaSi_OK;

    /* ............... getting the hardware semaphore ..................... */
    /* -------------------------------------------------------------------- */

    err = SaSi_PalMutexLock(&sasiAsymCryptoMutex, SASI_INFINITE);
    if (err != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    /* ------------------------------------------------------------------------ */
    /* initialize the PKA engine on default mode with size of registers       */
    /* ------------------------------------------------------------------------ */

    err = PKA_InitPka(sizeInBits, 0 /* sizeInWords */, pkaRegCount);
    if (err != SASI_SUCCESS) {
        SaSi_PalMutexUnlock(&sasiAsymCryptoMutex);
    }
    return err;
}

void PKA_FinishAndMutexUnlock(uint32_t pkaRegCount)
{
    // clear used registers
    if (pkaRegCount > 0) {
        pkaRegCount = SaSi_MIN(PKA_MAX_COUNT_OF_PHYS_MEM_REGS - 2, pkaRegCount);
        /* clear used PKA registers for security goals */
        PKA_ClearBlockOfRegs(PKA_REG_N /* FirstReg */, pkaRegCount, LEN_ID_MAX_BITS /* LenID */);
    }

    /* Finish PKA operations (waiting PKI done and close PKA clocks) */
    PKA_FinishPka();

    /* release the hardware semaphore */
    if (SaSi_PalMutexUnlock(&sasiAsymCryptoMutex) != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to release mutex\n");
    }
}

void PKA_ClearAllPka(void)
{
    uint32_t pkaRegCount = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;
    uint32_t regSizeInBits =
        ((SASI_PKA_SRAM_SIZE_IN_KBYTES * SASI_1K_SIZE_IN_BYTES * SASI_BITS_IN_BYTE) / PKA_MAX_COUNT_OF_PHYS_MEM_REGS) -
        SASI_PKA_WORD_SIZE_IN_BITS;

    if (PKA_InitAndMutexLock(regSizeInBits, &pkaRegCount) != SASI_SUCCESS) {
        return;
    }

    PKA_FinishAndMutexUnlock(pkaRegCount);
    return;
}
