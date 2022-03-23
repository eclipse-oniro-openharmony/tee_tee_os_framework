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
#include "ssi_pal_mutex.h"
#include "ssi_hal_plat.h"
#include "ssi_sram_map.h"
#include "dx_sasi_kernel.h"
#include "ssi_regs.h"
#include "sasi_common_math.h"
#include "pka_hw_defs.h"
#include "pka_export.h"
#include "pka_ut.h"
#include "pka.h"
#include "pka_error.h"
#ifdef DEBUG
#include <assert.h>
#endif

/* *********************** Defines **************************** */
extern const int8_t regTemps[PKA_MAX_COUNT_OF_PHYS_MEM_REGS];

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */
extern SaSi_PalMutex sasiAsymCryptoMutex;

#if defined PKA_DEBUG && defined DEBUG
uint32_t tempRes[PKA_MAX_REGISTER_SIZE_IN_32BIT_WORDS];
uint32_t tempRes1[PKA_MAX_REGISTER_SIZE_IN_32BIT_WORDS];
#endif

/* *********************** Public Functions **************************** */

/* ********************************************************************* */
/* *********       PKA initialisation functions and macros      ******** */
/* ********************************************************************* */

/* **********   LLF_PKI_PKA_DivLongNum function      ******************** */
/*
 * @brief The function divides long number A*(2^S) by B:
 *            Res =  A*(2^S) / B,  remainder A = A*(2^S) % B.
 *        where: A,B - are numbers of size, which is not grate than, maximal operands size,
 *               and B > 2^S;
 *               S  - exponent of binary factor of A.
 *               ^  - exponentiation operator.
 *
 *        The function algorithm:
 *
 *        1. Let nWords = S/32; nBits = S % 32;
 *        2. Set Res = 0, rT1 = OpA;
 *        3. for(i=0; i<=nWords; i++) do:
 *            3.1. if(i < nWords )
 *                   s1 = 32;
 *                 else
 *                   s1 = nBits;
 *            3.2. rT1 = rT1 << s1;
 *            3.3. call PKA_div for calculating the quotient and remainder:
 *                      rT2 = floor(rT1/opB) //quotient;
 *                      rT1 = rT1 % opB      //remainder (is in rT1 register);
 *            3.4. Res = (Res << s1) + rT2;
 *           end do;
 *        4. Exit.
 *
 *        Assuming:
 *                  - 5 PKA registers are used: OpA, OpB, Res, rT1, rT2.
 *                  - The registers sizes and mapping tables are set on default mode
 *                    according to operands size.
 *                  - The PKA clocks are initialized.
 *        NOTE !   Operand OpA shall be overwritten by remainder.
 *
 * @param[in] LenID    - ID of operation size (modSize+32).
 * @param[in] OpA      - Operand A: virtual register pointer of A .
 * @param[in] S        - exponent of binary factor of A.
 * @param[in] OpB      - Operand B: virtual register pointer of B .
 * @param[in] Res      - Virtual register pointer for result quotient.
 * @param[in] rT1      - Virtual pointer to remainder.
 * @param[in] rT2      - Virtual pointer of temp register.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure an error code:
 *
 *
 */
static SaSiError_t PKA_DivLongNum(uint8_t LenID, int8_t OpA, uint32_t S, int8_t OpB, int8_t Res, /* div result - out */
                                  int8_t rT1,                                                    /* remainder -  out */
                                  int8_t rT2)
{
    /* LOCAL DECLARATIONS */

    /* local variables */
    uint32_t nBits, nWords;

    /* loop variable */
    uint32_t i;

    /* current shift count */
    int8_t s1 = 0;

    /* FUNCTION LOGIC */

    /* initializations */

    /* calculate shifting parameters (words and bits ) */
    nWords = (CALC_FULL_32BIT_WORDS((uint32_t)S));
    nBits  = (uint32_t)S % SASI_BITS_IN_32BIT_WORD;

    /* copy operand OpA (including extra word) into temp reg rT1 */
    PKA_COPY(LEN_ID_MAX_BITS, rT1 /* dst */, OpA /* src */);

    /* set Res = 0 (including extra word) */
    PKA_2CLEAR(LEN_ID_MAX_BITS, Res /* dst */);

    /* ---------------------------------------------------- */
    /* Step 1.  Shifting and dividing loop                */
    /* ---------------------------------------------------- */

    for (i = 0; i < nWords; i++) {
        /* 3.1 set shift value s1  */
        if (i > 0)
            s1 = SASI_BITS_IN_32BIT_WORD;
        else
            s1 = nBits;

        /* 3.2. shift: rT1 = rT1 * 2**s1 (in code (s1-1), because PKA performs S+1 shifts) */
        if (s1 > 0) {
            PKA_SHL_FILL0(LenID + 1, rT1 /* Res */, rT1 /* OpA */, (s1 - 1) /* S */);
        }

        /* 3.3. perform PKA_DIV for calculating a quotient rT2 = floor(rT1 / N)
                and remainder rT1 = rT1 % OpB  */
        PKA_DIV(LenID + 1, rT2 /* Res */, rT1 /* OpA */, OpB /* B */);

#ifdef LLF_PKI_PKA_DEBUG_
        /* debug copy result into temp buffer */
        SaSi_MemSetZero((uint8_t *)tempRes, sizeof(tempRes));
        PKA_CopyDataFromPkaReg(tempRes /* dst_ptr */, RegSizeWords, rT1 /* srcReg */);
#endif

        /* 3.4. Res = Res * 2**s1 + Res;   */
        if (s1 > 0) {
            PKA_SHL_FILL0(LenID + 1, Res /* Res */, Res /* OpA */, (s1 - 1) /* S */);
        }

        PKA_ADD(LenID + 1, Res /* Res */, Res /* OpA */, rT2 /* OpB */);
    }

    PKA_WAIT_ON_PKA_DONE();

    return SaSi_OK;

} /* END OF PKA_DivLongNum */

/* **********      PKA_SetRegsMapTab function      ******************** */
/*
 * @brief This function initializes the PKA registers sizes table.
 *
 *   The function checks input parameters and sets the physical memory registers mapping-table
 *   according to parameters, passed by the user:
 *     - start address of register 0 is the start address of PKA data registers memory
 *       SASI_SRAM_PKA_BASE_ADDRESS (defined in ssi_sram_map.h file);
 *     - special registers are set as follows: N=0,NP=1,T0=30,T1=31;
 *     - all registers have the same size, equalled to given size;
 *
 * @param[in] countOfRegs  - The count of registeres, requirred by the user.
 * @param[in] regSizeInPkaWords - Sise of registers in PKA big words (e.g. 128-bit words).
 *
 * @return - no return value
 *
 */
static void PKA_SetRegsMapTab(int32_t countOfRegs, int32_t regSizeInPkaWords)
{
    /* LOCAL DECLARATIONS */

    uint32_t currentAddr;
    int32_t i;

    /* FUNCTION LOGIC */

    /* start addres of PKA mem. */
    currentAddr = SASI_SRAM_PKA_BASE_ADDRESS;

    /* set addresses of the user requested registers (excluding T0,T1) */
    for (i = 0; i < PKA_MAX_COUNT_OF_PHYS_MEM_REGS - 2; i++) {
        if (i < countOfRegs - 2) {
            SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, MEMORY_MAP0) + i * sizeof(uint32_t), currentAddr);
            currentAddr += regSizeInPkaWords * PKA_WORD_SIZE_IN_32BIT_WORDS;
        } else {
            /* write designation, that PKI entry is not in use */
            SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, MEMORY_MAP0) + i * sizeof(uint32_t),
                                    PKA_ADDRESS_ENTRY_NOT_USED);
        }
    }
    /* set addresses of 2 temp registers: T0=30, T1=31 */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, MEMORY_MAP0) + 30 * sizeof(uint32_t), currentAddr);
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, MEMORY_MAP0) + 31 * sizeof(uint32_t),
                            currentAddr + regSizeInPkaWords * PKA_WORD_SIZE_IN_32BIT_WORDS);

    /* set default virtual addresses of N,NP,T0,T1 registers into N_NP_T0_T1_Reg */
    PKA_DEFAULT_N_NP_T0_T1_REG();

    return;

} /* END of the finction  PKA_SetRegsMapTab */

/* **********      PKA_SetRegsSizesTab function      ******************** */
/*
 * @brief This function initializes the PKA registers sizes table.
 *
 *      The function sets sizes table as follows:
 *            -  tab[0] = MaxSizeBits; //maximal size, usually this is exact modulus size in bits
 *            -  tab[1] = Extended size with extra bits, aligned to big words.
 *            -  other entrie,
                uint32_t  Xs = PKA_SIZE_ENTRY_NOT_USED, means - not used.
 *
 * @param[in] opSizeInBits - Size of PKA operations (modulus) in bits. The value must be in interval
 *                          from defined Min. to Max. size bits.
 * @param[in] regSizeInPkaWords - Sise of registers in PKA big words (e.g. 128-bit words).
 *
 * @return - no return value
 *
 */
void PKA_SetRegsSizesTab(uint32_t opSizeInBits, int32_t regSizeInPkaWords)
{
    /* LOCAL DECLARATIONS */

    uint32_t i;

    /* FUNCTION LOGIC */

    /* Set exact op. size */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_L0), opSizeInBits);
    /* Set size with extra bits aligned to big words */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_L0) + 4, GET_FULL_OP_SIZE_BITS(opSizeInBits));

    /* remaining entries set to PKA_SIZE_ENTRY_NOT_USED for debugging goals */
    for (i = 2; i < PKA_NUM_OF_PKA_LEN_IDS_REGS; i++) {
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_L0) + 4 * i, PKA_SIZE_ENTRY_NOT_USED);
    }

    PKA_SetRegSize(regSizeInPkaWords * SASI_PKA_WORD_SIZE_IN_BITS, LEN_ID_MAX_BITS);

    return;

} /* END of the finction  PKA_SetRegsSizesTab */

/* **********      PKA_InitPka function      ******************** */
/*
 * @brief This function initializes the PKA engine.
 *
 *    The function performs the following:
 *      - initializes the PKA_SizesTable, PKA_MappingTable and special register
 *        N_NP_T0_T1 according to user passed register sizes, registers mapping
 *        and default N_NP_T0_T1 value.
 *
 *    The function calls the PKA_SetRegsSizesTab  and PKA_SetRegsMapTab
 *    functions and sets N_NP_T0_T1 value into N_NP_T0_T1 register.
 *    Notes:
 *            - See remarks to PKA_SetRegsSizesTab and PKA_SetRegsMapTab functions.
 *            - The function allocates one additional word for each register if it is needed for extra bits.
 *
 * @param[in] opSizeInBits  - Operation (modulus) exact size in bits. The value must
 *                    be in interval from defined min. to  max. size in bits.
 * @param[in] regSizeInPkaWords  - PKA register size. not exact for operation (== modulus)
 * @param[in/out] pRegsCount  - as input - required registers for operation.
 *                 as output - actual available regs, must be at least as required
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure an error code:
 *                       PKA_REGISTER_SIZES_ERROR
 *                       PKA_ENTRIES_COUNT_ERROR
 *                       PKA_NOT_ENOUGH_MEMORY_ERROR
 *
 */
SaSiError_t PKA_InitPka(uint32_t opSizeInBits,      /* in */
                        uint32_t regSizeInPkaWords, /* in */
                        uint32_t *pRegsCount)       /* out */
{
    /* LOCAL DECLARATIONS */

    int32_t regsCount;
    uint32_t regSizeIn32BitWords;
    uint32_t minRegSizeInPkaWords;

    /* FUNCTION LOGIC */
    /* check  input  */
    if (opSizeInBits < PKA_MIN_OPERATION_SIZE_BITS || opSizeInBits > PKA_MAX_OPERATION_SIZE_BITS) {
        return PKA_REGISTER_SIZES_ERROR;
    }

    /* calculate pka register size */
    if (opSizeInBits < (2 * (SASI_PKA_WORD_SIZE_IN_BITS + PKA_EXTRA_BITS))) {
        regSizeIn32BitWords = CALC_FULL_32BIT_WORDS(opSizeInBits + SASI_PKA_WORD_SIZE_IN_BITS + PKA_EXTRA_BITS - 1);
        if ((opSizeInBits + SASI_PKA_WORD_SIZE_IN_BITS + PKA_EXTRA_BITS - 1) % SASI_BITS_IN_32BIT_WORD) {
            regSizeIn32BitWords++;
        }
    } else {
        regSizeIn32BitWords = CALC_FULL_32BIT_WORDS(opSizeInBits);
    }

    minRegSizeInPkaWords = GET_FULL_OP_SIZE_PKA_WORDS(regSizeIn32BitWords * SASI_BITS_IN_32BIT_WORD);

    /* check given regs size or set it, if is not given */
    if (regSizeInPkaWords > 0) {
        if (regSizeInPkaWords < minRegSizeInPkaWords)
            return PKA_REGISTER_SIZES_ERROR;
    } else {
        regSizeInPkaWords = minRegSizeInPkaWords;
    }

    /* actually avaliable count of PKA registers */
    regsCount = SaSi_MIN(SASI_SRAM_PKA_SIZE_IN_BYTES / (regSizeInPkaWords * PKA_WORD_SIZE_IN_BYTES),
                         PKA_MAX_COUNT_OF_PHYS_MEM_REGS);

    if (pRegsCount != NULL) {
#ifdef PKA_DEBUG
        // checking number of registers are enough to execute this function
        if ((size_t)regsCount < *pRegsCount) {
            return PKA_REGS_COUNT_ERROR;
        }
#endif
        *pRegsCount = regsCount;
    }

    /*     enabling the PKA clocks      */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_CLK_ENABLE), 0x1UL);

    /* setting the PKA registers mapping table */
    /* ----------------------------------------- */
    PKA_SetRegsMapTab(regsCount, regSizeInPkaWords);

    /* setting the PKA registers sizes table   */
    /* ----------------------------------------- */
    PKA_SetRegsSizesTab(opSizeInBits, regSizeInPkaWords);

    /* ......  End of function ...... */
    return SaSi_OK;
}

/*
 * The function uses physical data pointers to calculate and output
 * the Barrett tag Np.
 *
 *  For RSA it uses truncated sizes:
 *      Np = truncated(2^(3*A+3*X-1) / ceiling(n/(2^(N-2*A-2*X)));
 *  For ECC - full sizes of not truncated input arguments:
 *      Np = truncated(2^(N+A+X-1) / n);
 *
 * @author reuvenl (5/1/2014)
 *
 * @param [out] pNp - The pointer to the Barrett tag Np buffer. If pNp = Null,
 *        the function not outputs calculated Np.
 * @param [in] pN - The pointer to the modulus n.
 * @param [in] sizeNbits - The exact size of the modulus.
 *
 * @return  - On success SaSi_OK is returned, on failure an error code.
 */
SaSiError_t PKA_CalcNp(uint32_t *pNp, uint32_t *pN, uint32_t sizeNbits)
{
    SaSiError_t err     = 0;
    uint32_t A          = SASI_PKA_WORD_SIZE_IN_BITS;
    uint32_t X          = PKA_EXTRA_BITS;
    uint32_t pkaReqRegs = 6;

    /* Sizes in words and bits  */
    int32_t wN, wNp;

    /* usage of PKA registers */
    int8_t rN  = PKA_REG_N;
    int8_t rNp = PKA_REG_NP;
    int8_t rT2 = regTemps[2];
    int8_t rT4 = regTemps[4];

    /* Calc. sizes of modulus in words and reminder in bits */
    wN  = CALC_FULL_32BIT_WORDS(sizeNbits);
    wNp = CALC_FULL_32BIT_WORDS(A + X - 1);

    err = PKA_InitAndMutexLock(sizeNbits, &pkaReqRegs);
    if (err != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }
    /* Set modulus in T1 */
    PKA_CopyDataIntoPkaReg(rN /* dstReg */, LEN_ID_MAX_BITS /* lenId */, pN /* src_ptr */, wN);
    err = PKA_CalcNpIntoPkaReg(LEN_ID_N_BITS, sizeNbits, rN /* regN */, rNp /* regNp */, rT2, rT4);
    if (err != SASI_SUCCESS) {
        goto End;
    }
    // ! TBD  ceiling
    /* Output Np */
    PKA_CopyDataFromPkaReg(pNp /* dst_ptr */, wNp, rNp /* srcReg */);
End:
    PKA_FinishAndMutexUnlock(pkaReqRegs);

    return err;
}

/*
 * The function uses physical data pointers to calculate and output
 * the Barrett tag Np.
 *
 *  For RSA it uses truncated sizes:
 *      Np = truncated(2^(3*A+3*X-1) / ceiling(n/(2^(N-2*A-2*X)));
 *  For ECC - full sizes of not truncated input arguments:
 *      Np = truncated(2^(N+A+X-1) / n);
 *
 *      function assumes modulus in PKA reg 0, and output is to PKA reg 1
 *
 * @author reuvenl (5/1/2014)
 *
 * @param [in] sizeNbits - The exact size of the modulus.
 *
 * @return  - On success SaSi_OK is returned, on failure an error code.
 */
SaSiError_t PKA_CalcNpIntoPkaReg(uint32_t lenId, uint32_t sizeNbits, int8_t regN,
                                 int8_t regNp, // out
                                 int8_t regTemp1, int8_t regTempN)
{
    SaSiError_t err = 0;
    int32_t i;
    uint32_t A = SASI_PKA_WORD_SIZE_IN_BITS;
    uint32_t X = PKA_EXTRA_BITS;

    /* Sizes in words and bits  */
    int32_t wT, bNom, wNom;
    uint32_t val;
    int32_t sh, st;

    // clear temp registers
    PKA_2CLEAR(LEN_ID_MAX_BITS, regTemp1);
    PKA_2CLEAR(LEN_ID_MAX_BITS, regTempN);
    PKA_2CLEAR(LEN_ID_MAX_BITS, regNp);

    // copy modulus (regN) into temprarty register - regTempN
    PKA_COPY(LEN_ID_MAX_BITS /* LenID */, regTempN /* OpDest */, regN /* OpSrc */);

    /* ----------------------------------------------- */
    if (sizeNbits <= (2 * A + 2 * X)) {
        wNom = CALC_FULL_32BIT_WORDS(sizeNbits + A + X - 1);
        /* Sizes of nominator (N+A+X-1) in 32-bit words */
        bNom = (sizeNbits + A + X - 1) % SASI_BITS_IN_32BIT_WORD; /* remain bits */
        if (bNom) {
            val = 1UL << bNom;
        } else {
            wNom++;
            val = 1UL;
        }

        /* Set rT2 = 2^(N+A+X-1) */
        PKA_WRITE_WORD_TO_REG(val, wNom - 1, regTemp1);
        // use LEN_ID_MAX_BITS for small sizes, since lenId is exact mod size which is not enought in this case!!!
        PKA_DIV(LEN_ID_MAX_BITS /* LenID */, regNp, regTemp1, regTempN);
    }
    /* If  (N > 2*A + 2*X) - truncated */
    /* --------------------------------- */
    else {
        /* Set rT1 = 2^D, where D=(3*A+3*X-1) division nominator size */
        /* ------------------------------------------------------------ */

        wNom = CALC_FULL_32BIT_WORDS(3 * A + 3 * X - 1); /* words count in nominator */
        /* Calc. sizes of Nominator */
        bNom = (3 * A + 3 * X - 1) % SASI_BITS_IN_32BIT_WORD; /* remain bits count */
        if (bNom) {
            val = 1UL << bNom;
        } else {
            wNom++;
            val = 1UL;
        }

        /* Set rT1 = 2^D, where D=(3*A+3*X-1) */
        PKA_WRITE_WORD_TO_REG(val, wNom - 1, regTemp1);

        /* Set rN = high part of the modulus as divisor */
        /* ----------------------------------------------- */

        /* count low bits to truncate the modulus */
        st = sizeNbits - 2 * A - 2 * X;
        /* count of words to truncate */
        wT = st / SASI_BITS_IN_32BIT_WORD;
        /* shift for truncation */
        sh = st % SASI_BITS_IN_32BIT_WORD;

        /* prevent further ceiling increment, if it not needed */
        PKA_SUB_IM(lenId + 1 /* LenID */, regTempN, regTempN, 1 /* OpBIm */);

        /* truncate modulus by words and then by bits */
        for (i = 0; i < wT; i++) {
            PKA_SHR_FILL0(lenId + 1 /* LenID */, regTempN, regTempN, SASI_BITS_IN_32BIT_WORD - 1);
        }
        if (sh) {
            PKA_SHR_FILL0(lenId + 1 /* LenID */, regTempN, regTempN, sh - 1);
        }

        /* Ceiling */
        PKA_ADD_IM(lenId + 1 /* LenID */, regTempN, regTempN, 1 /* OpBIm */);
        PKA_DIV(LEN_ID_MAX_BITS /* LenID */, regNp, regTemp1,
                regTempN); // use LEN_ID_MAX_BITS to make sure we catch the whole size
    }

    // clear temp registers
    PKA_2CLEAR(LEN_ID_MAX_BITS, regTemp1);
    PKA_2CLEAR(LEN_ID_MAX_BITS, regTempN);

    return err;
}

/* **********      PKA_ClearBlockOfRegs function      ******************** */
/*
 * @brief This function clears block of PKA registers + temp registers 30,31.
 *
 *        Assumings: - PKA is initialized properly.
 *                   - Length of extended (by word) registers is placed into LenID entry of
 *                 sizes table.
 *               - Meets condition: firstReg <= 30.
 *               - All registers, given to cleaning, are inside the allowed memory.
 *
 * @param[in] firstReg    - Virtual address (number) of first register in block.
 * @param[in] countOfRegs - Count of registers to clear.
 * @param[in] LenId       - ID of entry of regsSizesTable defines register length
 *                          with word extension.
 *
 * @return - no return parameters.
 *
 */
void PKA_ClearBlockOfRegs(uint32_t firstReg,   /* in */
                          int32_t countOfRegs, /* in */
                          uint32_t LenID /* in */)
{
    /* LOCAL DECLARATIONS */
    int32_t i;
    uint32_t size, addr;

    /* FUNCTION LOGIC */

    /* check registers count */
    ASSERT(firstReg <= 30);

    /* calculate size of register in words */
    PKA_ReadRegSize(size, LenID);
    size = CALC_FULL_32BIT_WORDS(size);

    /* correction for max. count regs. and memory size */
    if (firstReg + countOfRegs > 30) {
        countOfRegs = 30 - firstReg;
    }
    if ((firstReg + countOfRegs) * size > SASI_SRAM_PKA_SIZE_IN_BYTES / sizeof(uint32_t)) {
        countOfRegs = ((SASI_SRAM_PKA_SIZE_IN_BYTES / sizeof(uint32_t)) / size) - firstReg;
    }

    /* clear ordinary and temp registers without PKA operations */

    for (i = 0; i < countOfRegs; i++) {
        PKA_GetRegAddress(firstReg + i /* VirtReg */, addr /* physAddr */);
        PKA_HW_CLEAR_PKA_MEM(addr, size);
    }
    PKA_GetRegAddress(PKA_REG_T1 /* VirtReg */, addr /* physAddr */);
    PKA_HW_CLEAR_PKA_MEM(addr, size);
    PKA_GetRegAddress(PKA_REG_T0 /* VirtReg */, addr /* physAddr */);
    PKA_HW_CLEAR_PKA_MEM(addr, size);

    return;
}

/* **********      PKA_CopyDataFromPkaReg      ******************** */
/*
 * @brief This function copies data from PKA register into output buffer .
 *
 *        Assumings: - PKA is initialized.
 *                   - Length of extended (by word) registers is placed into LenID entry of
 *                     sizes table.
 *                   - If the extra word of register must be cleared also the user must
 *                     set LenID according to extended register size
 *
 * @param[in] srcReg       - Virtual address (number) of source PKA register.
 * @param[in] dst_ptr      - Pointer to destination buffer.
 * @param[in] sizeBytes - Source size in bytes.
 *
 * @return - no return parameters.
 *
 */
void PKA_CopyDataFromPkaReg(uint32_t *dst_ptr,  /* out */
                            uint32_t sizeWords, /* in */
                            uint32_t srcReg /* in */)
{
    /* LOCAL DECLARATIONS */

    /* current register address and size */
    uint32_t currAddr;

    /* FUNCTION LOGIC */

    PKA_GetRegAddress(srcReg, currAddr /* PhysAddr */);
    PKA_HW_READ_BLOCK_FROM_PKA_MEM(currAddr, dst_ptr, sizeWords);

    return;

} /* END OF function PKA_CopyDataFromPkaReg */

/* **********      PKA_CopyDataIntoPkaReg function      ******************** */
/*
 * @brief This function  copies source data into PKA register .
 *
 *        Assumings: - PKA is initialized.
 *                   - Length of extended (by word) registers is placed into LenID entry of
 *                     sizes table.
 *                   - If the extra word of register must be cleared also the user must
 *                     set LenID according to extended register size
 *
 * @param[in] dstReg       - Virtual address (number) of destination register.
 * @param[in] LenId        - ID of entry of regsSizesTable defines registers length with word extension.
 * @param[in] src_ptr      - Pointer to source buffer.
 * @param[in] sizeWords    - Data size in words.
 *
 * @return - no return parameters.
 *
 */
void PKA_CopyDataIntoPkaReg(uint32_t dstReg,         /* out */
                            uint32_t LenID,          /* in */
                            const uint32_t *src_ptr, /* in */
                            uint32_t sizeWords /* in */)
{
    /* LOCAL DECLARATIONS */

    /* current register address and size */
    uint32_t currAddr;
    uint32_t regSize;

    /* FUNCTION LOGIC */

    /* copy data from src buffer into PKA register with 0-padding  *
     *  in the last PKA-word                       */

    PKA_GetRegAddress(dstReg, currAddr);
    PKA_HW_LOAD_BLOCK_TO_PKA_MEM(currAddr, src_ptr, sizeWords);

    /* data size aligned to full PKA-word */
    sizeWords =
        ((sizeWords + PKA_WORD_SIZE_IN_32BIT_WORDS - 1) / PKA_WORD_SIZE_IN_32BIT_WORDS) * PKA_WORD_SIZE_IN_32BIT_WORDS;
    currAddr = currAddr + sizeWords;

    /* register size in words */
    PKA_ReadRegSize(regSize, LenID);
    regSize = CALC_FULL_32BIT_WORDS(regSize);

    /* zeroe not significant high words of the register */
    if (regSize > sizeWords) {
        PKA_HW_CLEAR_PKA_MEM(currAddr, regSize - sizeWords);
    }

#if defined PKA_DEBUG && defined DEBUG
    /* ! PKA_DEBUG */
    PKA_COPY(LEN_ID_MAX_BITS /* LenID */, dstReg, dstReg);
#endif
    return;
} /* END OF function PKA_CopyDataIntoPkaReg */

void PKA_FinishPka(void)
{
    /*     disable the PKA clocks      */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_CLK_ENABLE), 0x0UL);
    return;
}

void PKA_ClearPkaRegWords(uint32_t pkaReg, /* in */
                          uint32_t addrWordOffset /* in */)
{
    /* current register address and size */
    uint32_t currAddr;
    uint32_t regSize;

    /* copy data from src buffer into PKA register with 0-padding  *
     *  in the last PKA-word                       */
    PKA_GetRegAddress(pkaReg, currAddr);
    currAddr = currAddr + addrWordOffset;

    /* register size in words */
    PKA_ReadRegSize(regSize, LEN_ID_MAX_BITS);
    regSize = CALC_FULL_32BIT_WORDS(regSize);

    /* zeroe not significant high words of the register */
    if (regSize > addrWordOffset) {
        PKA_HW_CLEAR_PKA_MEM(currAddr, regSize - addrWordOffset);
    }

    return;
}

/*
 * The function returns result (x == y mod n).
 * Assumed: n - in reg. 0, lenId = 1.
 *
 * @author reuvenl (6/20/2014)
 *
 * @param x - first reg.
 * @param y - second reg.
 * @param tt1, tt2 - temp PKA regs.
 *
 * @return bool
 */
bool pka_mod_equal(uint32_t x, uint32_t y, uint32_t t1, uint32_t t2)
{
    uint32_t status;
    PKA_REDUCE(LEN_ID_N_BITS, x, t1);
    PKA_REDUCE(LEN_ID_N_BITS, y, t2);
    PKA_COMPARE_STATUS(LEN_ID_N_PKA_REG_BITS, t1, t2, status);
    return (bool)(status == 1);
}

/* **************************************************************************************** */
/*
 *
 * Function name: LLF_PKI_RSA_Call_Div
 *
 * Description: This function performs division of big numbers, passed by physical pointers,
 *              using the PKA.
 *              .
 *     Computes modRes = A mod B. divRes_ptr = floor(A/B)
 *     Lengths: A[ALen], B[BLen], modRes[BLen], divRes[ALen].
 *     Assumes:  c > 0.
 *
 *     PKA registers using: A=>r2, B=>r3, divRes=>r4, modRes=>r2 (r2 is rewritten by remainder).
 *
 * Author: R.Levin
 *
 * Last Revision: 1.00.00
 *
 * @param[in] A_ptr          - The pointer to numerator A vector.
 * @param[in] ASizeInWords   - Length of numerator A in words.
 * @param[in] B_ptr          - The pointer to divider B (modulus).
 * @param[in] BSizeInWords   - The size of B vector in words.
 * @param[out] modRes_ptr    - The pointer to modulus result (reminder of division).
 * @param[out] divRes_ptr    - The pointer to result of division.
 * @param[in] tempBuff_ptr   - The pointer to temp buffer - not used, may be set NULL.
 *
 * @return  - no return value
 *
 * Update History:
 * Rev 1.00.00, Date 4 Feb. 2008,
 *
 */

SaSiError_t LLF_PKI_RSA_Call_Div(uint32_t *A_ptr, uint32_t ASizeInWords, uint32_t *B_ptr, uint32_t BSizeInWords,
                                 uint32_t *modRes_ptr, uint32_t *divRes_ptr, uint32_t *tempBuff_ptr)
{
    /* LOCAL DECLARATIONS */

    /* error identification */
    SaSiError_t Error = SaSi_OK;

    /* operation size */
    uint32_t opSizeWords;

    /* PKA status */
    uint32_t status;
    uint32_t pkaReqRegs = 6;
    int8_t rT2          = regTemps[2];
    int8_t rT3          = regTemps[3];
    int8_t rT4          = regTemps[4];

    /* FUNCTION LOGIC */

    /* ............... initialize local variables ......................... */
    /* -------------------------------------------------------------------- */

    /* for avoid compiler warning */
    tempBuff_ptr = tempBuff_ptr;

    opSizeWords = SaSi_MAX(ASizeInWords, BSizeInWords);

    /* ............... getting the hardware semaphore ..................... */
    /* -------------------------------------------------------------------- */

    Error = PKA_InitAndMutexLock(SASI_BITS_IN_32BIT_WORD * opSizeWords, &pkaReqRegs);
    if (Error != SaSi_OK) {
        return Error;
    }

    /* ------------------------------------------------------------------------ */
    /* copying all needed data into PKA memory before starting PKA operations */
    /* A=>r2, B=>r3,                                                          */
    /* ------------------------------------------------------------------------ */

    /* copy numerator into PKA register: A=>r2 */
    PKA_CopyDataIntoPkaReg(rT2 /* dstReg */, LEN_ID_MAX_BITS /* LenID */, A_ptr /* src_ptr */, ASizeInWords);

    /* copy divisor into PKA register: B=>r3 */
    PKA_CopyDataIntoPkaReg(rT3 /* dstReg */, LEN_ID_MAX_BITS /* LenID */, B_ptr /* src_ptr */, BSizeInWords);

    /* check, that divisor is not null, else return error */
    PKA_ADD_IM(LEN_ID_N_PKA_REG_BITS /* LenID */, rT4 /* Res */, rT3 /* OpA */, 0 /* Imm OpB */);
    PKA_GET_StatusAluOutZero(status);
    if (status == 1) {
        Error = PKA_DIVIDER_IS_NULL_ERROR;
        goto End;
    }

    /* ------------------------------------------------------------------------- */
    /* division in PKA: quotient: r4 = r2 / r3; remainder: r2 = r2 % r3        */
    /* ------------------------------------------------------------------------- */

    PKA_DIV(LEN_ID_N_PKA_REG_BITS /* LenID */, rT4 /* Res */, rT2 /* OpA */, rT3 /* OpB */);

    /* ------------------------------------------------------------------------- */
    /*        output the results                                               */
    /* ------------------------------------------------------------------------- */

    if (divRes_ptr != NULL) {
        PKA_CopyDataFromPkaReg(divRes_ptr, ASizeInWords, rT4 /* srcReg */);
    }

    if (modRes_ptr != NULL) {
        PKA_CopyDataFromPkaReg(modRes_ptr, BSizeInWords, rT2 /* srcReg */);
    }

/* ---------------------------------------------------------------------- */
/* .............. end of the function ................................... */
/* ---------------------------------------------------------------------- */
End:

    PKA_FinishAndMutexUnlock(pkaReqRegs);

    return Error;
}

/* **********      LLF_PKI_PKA_GetBitFromPkaReg     ******************** */
/*
 * @brief This function returns bit i from PKA register.
 *
 *
 * @param[in] rX       - Virtual pointer to PKA register.
 * @param[in] LenId    - ID of entry of regsSizesTable containing rX register length
 *                       with word extension.
 * @param[in] i        - number of bit to be tested.
 * @param[in] rT       - temp register. If it is not necessary to keep rX, then
 *                       set rT=rX for saving memory space.
 *
 * @return - returns the bit number i (counting from left).
 *
 */
uint8_t PKA_GetBitFromPkaReg(uint32_t rX, uint32_t LenID, int32_t i, uint32_t rT)
{
    /* LOCAL DECLARATIONS */

    /* loop variable */
    uint32_t j;

    /* number shifts by word and by bit */
    uint32_t numWords, numBits;

    uint32_t bitVal;

    /* copy extended rX=>rT */
    if (rX != rT)
        PKA_COPY(LEN_ID_MAX_BITS, rT /* dst */, rX /* src */);

    /* number shifts */
    numWords = i / SASI_BITS_IN_32BIT_WORD;
    numBits  = i % SASI_BITS_IN_32BIT_WORD;

    /* shift by words */
    for (j = 0; j < numWords; j++) {
        PKA_SHR_FILL0(LenID + 1, rT /* Result */, rT /* N */, SASI_BITS_IN_32BIT_WORD - 1 /* S */);
    }

    /* shift by bits */
    if (numBits >= 1)
        PKA_SHR_FILL0(LenID + 1, rT /* Result */, rT /* N */, numBits - 1 /* S */);

    /* test LS Bit */
    PKA_READ_BIT0(LenID + 1, rT /* */, bitVal);
    return (bitVal);

} /* END OF function LLF_PKI_PKA_GetBitFromPkaReg */

/* *******************     LLF_PKI_PKA_ExecFullModInv    ********************** */
/*
 * @brief This function calculates modular inversion Res = 1/B mod N for both odd and even modulus.
 *
 *        The function works with virtual pointers to PKA registers (sequence numbers)
 *        and does the following:
 *
 *        1. Checks the parity of modulus N (in register 0) and operand B. If they both are even,
 *           returns an Error (inverse is not exist)
 *        2. If the modulus is odd, then calls the LLF_PKI_PKA_ModInv function for calculating
 *           the inverse.
 *        3. If the modulus is even, then the function performs the following:
 *           3.1  Saves modulus N: rT0<=N;
 *           3.2. Sets B into reg N: N<=B.
 *           3.3. Res = N^-1 mod B (call LLF_PKI_PKA_ModInv ); Restore mod: N<=rT0;
 *           3.4. rT0 = high(N*N^-1) = LLF_PKI_PKA_HMul(N,Res,rT0);
 *           3.5. Shift right rT0 >> 32;
 *           3.6. rT1 = low(N*N^-1) = LLF_PKI_PKA_LMul(N,Res,rT1);
 *           3.7. Res = rT0 / B : call LLF_PKI_PKA_LongDiv(rT0,B,Res);
 *           3.7. rT0 = rT1 / B : call LLF_PKI_PKA_Div(rT1,B,rT0);
 *           3.8. Res = Res + rT0 : ModAdd(Res,rT0,Res);
 *           3.9. If reminder of division > 0, then Res= Res+1;
 *           3.10. Res = N-Res;
 *        4. Exit.
 *
 *     NOTE:
 *       -  The operand B shal be rewritten by GCD(N,B).
 *       -  The function needs 6 PKA regs: N(0), OpB, Res, rT0, rT1, rT2.
 *       -  PKA sizes table entrys must be set:  0 - exact modSizeBits, 1 - modSizeBits+32 bits,
 *       -    Before executing modular operations, the modulus must be set into r0 register of PKA.
 *       -  The function not checks the input parameters, because they must be checked previously.
 *
 * @param[in] OpB   - Operand B: virtual register pointer. Valid values: 0 <= OpA <= 31.
 * @param[in] Res   - Virtual register pointer for result data. Valid values: 0 <= Res <= 31.
 * @param[in] LenID    - ID of the length of operands according to register sizes table
 *                       (means the number of entry in the table). Valid values: 0...7.
 * @param[in] rT0,rT1,rT2,rT3  - The virtual pointers to temp registers (sequence numbers).
 * @param[in] Tag        - The user defined value (Tag <= 31), used for indication goals.
 *
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure an error code:
 *                       LLF_PKI_PKA_ILLEGAL_OPCODE_ERROR
 *                       LLF_PKI_PKA_ILLEGAL_OPERAND_LEN_ERROR
 *                       LLF_PKI_PKA_ILLEGAL_OPERAND_TYPE_ERROR
 *                       LLF_PKI_PKA_ILLEGAL_OPERAND_ERROR
 *                       LLF_PKI_PKA_INVERSION_NOT_EXISTS_ERROR
 *
 */
SaSiError_t PKA_ExecFullModInv(int8_t OpB, /* in */
                               int8_t Res, /* in */
                               int8_t rT0, /* in */
                               int8_t rT1, /* in */
                               int8_t rT2, /* in */
                               int8_t rT3)
{
    /* LOCAL DECLARATIONS */

    /* error identification */
    SaSiError_t Error = SaSi_OK;

    /* virtual pointer to modulus register, by default: N=0 */
    uint8_t N = PKA_REG_N;

    uint32_t ModSizeBits, ModSizeWords;

    uint32_t status;
    uint32_t bitVal;

    /*  Initializations */

    /* FUNCTION LOGIC */

    /* get modulus size */
    PKA_ReadRegSize(ModSizeBits, LEN_ID_N_BITS);
    ModSizeWords = CALC_FULL_32BIT_WORDS(ModSizeBits);

    /* ------------------------------------------- */
    /* Step 1.  Check the parity of the modulus  */
    /* ------------------------------------------- */
    /* test: is the modulus even? */
    PKA_READ_BIT0(LEN_ID_N_PKA_REG_BITS, PKA_REG_N /* N */, bitVal);
    if (bitVal == 1 /* odd N */) {
        /* ------------------------------------------- */
        /* Step 2.  Process case of odd modulus      */
        /* ------------------------------------------- */
        PKA_MOD_INV(LEN_ID_N_BITS, Res, OpB);
    } else { /* even N */
        /* ------------------------------------------- */
        /* Step 3. Process case of even modulus      */
        /* ------------------------------------------- */

        /* ------------------------------------------------------------ */
        /* in case of even B: calculate GCD and return error message, */
        /*  that inverse does not exists                              */
        /* ------------------------------------------------------------ */
        /* check, is the operand B odd or even */
        PKA_READ_BIT0(LEN_ID_N_PKA_REG_BITS, OpB, bitVal);
        if (bitVal == 0) {
            return PKA_INVERSION_NOT_EXISTS_ERROR;
        }

        /* ------------------------------------------------------------ */
        /* in case of odd B: calculate modular inverse and GCD        */
        /* ------------------------------------------------------------ */

        /* 3.1. Save previous modulus also into rT0 and into rT1 (rT1 - working copy) */
        PKA_COPY(LEN_ID_MAX_BITS /* LenID */, rT0 /* OpDest */, N /* OpSrc */);
        PKA_COPY(LEN_ID_MAX_BITS /* LenID */, rT1 /* OpDest */, N /* OpSrc */);

        /* 3.2. Set OpB into modulus register 0 ) */
        PKA_COPY(LEN_ID_MAX_BITS /* LenID */, N /* OpDest */, OpB /* OpSrc */);

        /* 3.3 Calculate Res =  1/N mod B  */
        PKA_MOD_INV(LEN_ID_N_BITS /* LenID */, Res, rT1 /* mod N */);

        /* restore modulus */
        PKA_COPY(LEN_ID_MAX_BITS /* LenID */, N /* OpDest */, rT0 /* OpSrc */);

        /* 3.4. Calculate rT0 = PKA_MUL_HIGH(N*Res) i.e. HighHalf + 1 word of(N*Res)
                Note: LenId=0, because this operation adds extra word itself */
        PKA_MUL_HIGH(LEN_ID_N_BITS, rT0 /* Result */, N, Res);

        /* 3.5. Shift right rT0 for deleting 1 low word - no need in new HW */

        /* 3.6. Calculate rT2 = PKA_MUL_LOW(N*Res) i.e. LowHalf of(N*Res) */
        PKA_MUL_LOW(LEN_ID_N_BITS, rT2 /* Result */, N, Res);

        /* 3.6. Divide long num Res = (rT1 * 2**(ModSizeBits - 32))/B */
        Error = PKA_DivLongNum(LEN_ID_N_BITS,                                                    /* LenID of exact size */
                               rT0,                                                              /* numerator */
                               SASI_BITS_IN_32BIT_WORD * ModSizeWords + SASI_BITS_IN_32BIT_WORD, /* Shift */
                               OpB,                                                              /* divider */
                               Res,                                                              /* result */
                               rT1, rT3);

        if (Error != SaSi_OK) {
            return Error;
        }

        /* 3.7. Subtract 1 from low part and divide it by B */
        PKA_SUB_IM(LEN_ID_N_PKA_REG_BITS, rT2 /* Result */, rT2 /* numerat */, 1 /* OpB */);
        PKA_DIV(LEN_ID_N_PKA_REG_BITS, rT0 /* Result */, rT2 /* numerat */, OpB /* divider */);

        /* 3.8. Calculate: Res = Res+rT0, Res=Res+1, Res = N - Res; */
        PKA_ADD(LEN_ID_N_PKA_REG_BITS, Res, Res, rT0);

        /* 3.9. If remainder rT2 is not 0, then add 1 to rT0 result */
        PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, rT2 /* OpA */, 0 /* OpB */, status);
        if (status != 1) {
            PKA_ADD_IM(LEN_ID_N_PKA_REG_BITS, Res, Res, 1);
        }
        /* 3.10. Res = N - Res; */
        PKA_SUB(LEN_ID_N_PKA_REG_BITS, Res, N, Res);
    }

    /* End of function */

    return Error;

} /* END OF function PKA_ExecFullModInv */

/* **************************************************************************************** */
/*
 *
 * Function name: LLF_PKI_RSA_CallRMul
 *
 * Description: This function performs multiplication of big numbers, passed by physical
 *              pointers, using the PKA.
 *
 *        The RMul operation is : (A * B)
 *
 *        The function performs the following algorithm:
 *
 *
 * @param[in] A_ptr       - The pointer of A words array (LS word is left most).
 * @param[in] B_ptr       - The pointer of B words array (LS word is left most).
 * @param[in] ASizeInBits - The size of vectors in bits.
 * @param[out] Res_ptr    - The pointer to the result buffer.
 *
 * @return SaSiError_t - SaSi_OK
 */
SaSiError_t LLF_PKI_RSA_CallRMul(uint32_t *A_ptr, uint32_t ASizeInBits, uint32_t *B_ptr, uint32_t *Res_ptr)
{
    /* LOCAL DECLARATIONS */

    /* error identification */
    SaSiError_t Error = SaSi_OK;

    /* operation size */

    uint32_t OpSizeInWords;
    uint32_t pkaReqRegs = 6;
    int8_t rT2          = regTemps[2];
    int8_t rT3          = regTemps[3];
    int8_t rT4          = regTemps[4];

    /* FUNCTION LOGIC */

    /* ............... initialize local variables ......................... */
    /* -------------------------------------------------------------------- */

#ifdef LLF_PKI_PKA_DEBUG
    /* check the operands size */
    if (2 * ASizeInBits > PKA_MAX_OPERATION_SIZE_BITS)
        return PKA_ILLEGAL_OPERAND_LEN_ERROR;
#endif

    /* set operation size in words */
    if (CALC_FULL_32BIT_WORDS(2 * ASizeInBits) < CALC_FULL_32BIT_WORDS(PKA_MIN_OPERATION_SIZE_BITS))
        OpSizeInWords = CALC_FULL_32BIT_WORDS(PKA_MIN_OPERATION_SIZE_BITS);

    else
        OpSizeInWords = CALC_FULL_32BIT_WORDS(2 * ASizeInBits);

    Error = PKA_InitAndMutexLock(SASI_BITS_IN_32BIT_WORD * OpSizeInWords, &pkaReqRegs);
    if (Error != SaSi_OK) {
        return Error;
    }

    /* ------------------------------------------------------------------------ */
    /* copying all needed data into PKA memory before starting PKA operations */
    /* A=>r2, B=>r3,                                                          */
    /* ------------------------------------------------------------------------ */

    /* copy A into PKA register: A=>r2 */
    PKA_CopyDataIntoPkaReg(rT2 /* dstReg */, LEN_ID_MAX_BITS /* LenID */, A_ptr /* src_ptr */,
                           CALC_FULL_32BIT_WORDS(ASizeInBits));

    /* copy B into PKA register: B=>r2 */
    PKA_CopyDataIntoPkaReg(rT3 /* dstReg */, LEN_ID_MAX_BITS /* LenID */, B_ptr /* src_ptr */,
                           CALC_FULL_32BIT_WORDS(ASizeInBits));

    /* ------------------------------------------------------------------------- */
    /* multiply in PKA:  r4 = r2 * r3;                                         */
    /* ------------------------------------------------------------------------- */

    PKA_MUL_LOW(LEN_ID_N_PKA_REG_BITS /* lenId */, rT4 /* Res */, rT2 /* OpA */, rT3 /* OpB */);

    /* ------------------------------------------------------------------------- */
    /*        output the results                                               */
    /* ------------------------------------------------------------------------- */

    PKA_CopyDataFromPkaReg(Res_ptr, OpSizeInWords, rT4 /* srcReg */);

    /* ---------------------------------------------------------------------- */
    /* .............. end of the function ................................... */
    /* ---------------------------------------------------------------------- */

    PKA_FinishAndMutexUnlock(pkaReqRegs);

    return Error;
}

/* !
 * The function performs conditional swapping of two values in secure
 * mode
 *
 * if(swp == 1) {tmp = *x; *x = *y; *y = tmp;}
 *
 * \param x  - the pointer to x-variable
 * \param y  - the pointer to y-variable
 * \param swp - swapping condition [0,1]
 */
void PKA_ConditionalSecureSwapUint32(uint32_t *x, uint32_t *y, uint32_t swp)
{
    int32_t tmpX = *x;
    int32_t tmpY = *y;
    int32_t tmp  = tmpX ^ tmpY;
    swp          = -swp;
    tmp &= swp;
    *x = tmpX ^ tmp;
    *y = tmpY ^ tmp;
}
