/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_mem.h"
#include "sasi_common_math.h"
#include "pka_export.h"
#include "pka_ecc.h"
#include "pka_dbg.h"

/* temp buffers used for debugging of PKA operations */
#if defined PKA_DEBUG && defined DEBUG
uint32_t tempRes[PKA_MAX_REGISTER_SIZE_IN_32BIT_WORDS];
uint32_t tempRes1[PKA_MAX_REGISTER_SIZE_IN_32BIT_WORDS];

/*
 * The function prints label and PKA register as big endian bytes array.
 *
 * @author reuvenl (8/25/2013)
 *
 * @param label - label string.
 * @param reg - register virt. pointer.
 */
void pka_reg_print(const char *label, const uint32_t reg)
{
    uint32_t tmp[PKA_MAX_REGISTER_SIZE_IN_32BIT_WORDS] = { 0 };
    uint32_t sizeBits;
    uint32_t sizeBytes;
    uint32_t sizeWords;
    int32_t i;

    if (reg > PKA_REG_T1) {
        PKA_PRINTF("Can't print reg %d, reg is too big \n", reg);
        exit(1);
    }
    sizeBits  = PKA_GetRegEffectiveSizeInBits(reg);
    sizeBytes = CALC_FULL_BYTES(sizeBits);
    sizeWords = CALC_FULL_32BIT_WORDS(sizeBits);
    if ((sizeBytes > sizeof(tmp)) || ((sizeBits == 0) && (reg < PKA_REG_T0))) {
        PKA_PRINTF("Can't print reg %d, size in %d\n", reg, sizeBytes);
    }
    PKA_CopyDataFromPkaReg(tmp, sizeWords, reg);

    PKA_PRINTF("%s [%d] ", label, sizeBits);
    for (i = (sizeBytes - 1); i >= 0; i--) {
        PKA_PRINTF("%02X", ((uint8_t *)tmp)[i] & 0xFF);
    }
    PKA_PRINTF("\n");
}

/*
 * The function prints the label and 32-bit words buffer (LS-word is
 * a left most) as a big hexadecimal number (MS-digit is a left most).
 *
 * @param label - label string.
 * @param pBuf - 32-bit words buffer to print.
 * @param sizeWords - size of pBuff in 32-bi words.
 */
void pka_buf_print(const char *label, const uint32_t *pBuf, uint32_t sizeWords)
{
    uint32_t sizeBits;
    int32_t i;

    sizeBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pBuf, sizeWords);

    PKA_PRINTF("%s [%d] ", label, sizeBits);
    for (i = (sizeWords - 1); i >= 0; i--) {
        PKA_PRINTF("%08X", pBuf[i]);
    }
    PKA_PRINTF("\n");
}
#endif

#if defined PKA_DEBUG && defined DEBUG
/* **********    _PKA_ExecOperation (with virtual pointers)     **************** */
/*
 * @brief This function executes any allowed PKA mathematic operation according to
 *        user passed Opcode.
 *
 *        The function receives code of operation, virtual pointers to PKI registers
 *        (sequence number), for arguments and result, and operates PKA machine by writing
 *        full operation code into OPCODE register. Then the function calls macros for
 *        waiting the PKA pipe ready signal.
 *        If opcode is illegal or one of operands is illegal, the function returns an
 *        error code defined in pka_error.h file.
 *
 *        The user don't call this function directly. For user convenience, in llf_pki.h file  are
 *        given some macros for calling this function according to each performed operation.
 *
 *     NOTES:
 *       -    Before executing modular operations, the modulus must be set into N=r0 register of PKA.
 *       -    Before modular multiplication and exponentiation must be calculated and set into NP=r1
 *          register the Barrett modulus tag NP = 2**(sizeN+132) / N.
 *       -    In operations with immediate operands (IsImmediate bit = 1), the operand value (5-bit)
 *          is treated as sign-extended. That means: low 4 bits are treated as unsigned operand
 *          value in range 0-15 and bit 5 is a sign (with extension to all high bits of register,
 *          in which the full operand shall be set).
 *       -    In shift operations the 5-bits shift operand is treated as unsigned value in range 0-31
 *          (count of shifts is equaled to shift operand value + 1).
 *       -  The LMul operation gives the low half of multiplication result of length equaled to
 *          operation size. The leading not significant bits of the operands and result (including
 *          the the extra word) must be zeroed.
 *       -  The HMul operation gives the high half of multiplication result plus one high word of low
 *          half of full multiplication result. Therefore this result is by one word large, than
 *          operation size. The leading not significant bits of the operands and result,
 *          including extra word must be zeroed.
 *       -  The ModInv operation calculates Res = 1/OpB mod N for odd modulus. Operand A is ignored.
 *          In case of even modulus the function returns an error. Therefore in this case
 *          (also for odd modulus) the user may call the PKA_ExecFullModInv function.
 *
 * @param[in] Opcode   - The operation code according HW PKA definitions. Valid values: 0 - max Opcode.
 * @param[in] LenID    - ID of the length of operands according to register sizes table
 *                       (means the number of entry in the table). Valid values: 0...7.
 * @param[in] IsAImmed - If IsAImmed = 1, then operand A treated as immediate value, else -
 *                       as virtual register pointer. Valid values:    0,1.
 * @param[in] OpA      - Operand A: an immediate value or virtual register pointer, according to IsAImmed
 *                       IsAImmed parameter. Valid values: 0 <= OpA <= 31.
 * @param[in] IsBImmed - If IsBImmed = 1, then operand B treated as immediate value, else -
 *                       as virtual register pointer. Valid values:    0,1.
 * @param[in] OpB      - Operand B: an immediate value or virtual register pointer, according to IsAImmed
 *                       IsBImmed parameter. Valid values: 0 <= OpA <= 31.
 * @param[in] ResDiscard -    If ResDiscard = 1, then result is discarded.
 * @param[in] Res        - Virtual register pointer for result data.
 *                         Valid values: 0 <= Res <= 31. Value Res = RES_DISCARD means result must be discarded.
 * @param[in] Tag        - The user defined value (Tag <= 31), used for indication goals.
 *
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure an error code:
 *                       PKA_ILLEGAL_OPCODE_ERROR
 *                       PKA_ILLEGAL_OPERAND_LEN_ERROR
 *                       PKA_ILLEGAL_OPERAND_TYPE_ERROR
 *                       PKA_ILLEGAL_OPERAND_ERROR
 *                       PKA_INVERSION_NOT_EXISTS_ERROR
 */
SaSiError_t _PKA_ExecOperation(uint32_t Opcode,     /* in */
                               uint32_t LenID,      /* in */
                               uint32_t IsAImmed,   /* in */
                               uint32_t OpA,        /* in */
                               uint32_t IsBImmed,   /* in */
                               uint32_t OpB,        /* in */
                               uint32_t ResDiscard, /* in */
                               uint32_t Res,        /* in */
                               uint32_t Tag /* in */)

{
    /* LOCAL DECLARATIONS */

    /* error identification */
    SaSiError_t Error = SaSi_OK;

    /* full Operation Code word */
    uint32_t FullOpCode;

    /* testing status  */
    uint32_t status;
    /* register size */
    uint8_t OpPrint;
    uint32_t opSizeInBits, RegSizeWords;

    /* FUNCTION LOGIC */

    /* if Res == RES_DISCARD , then result is discarded */
    if (Res == (int8_t)RES_DISCARD) {
        ResDiscard = 1;
        Res        = 0;
    }

    /* set operation size according to LenID+1for debug copy and clearing registers */
    if (LenID & 1) {
        PKA_ReadRegSize(opSizeInBits, LenID);
    } else {
        PKA_ReadRegSize(opSizeInBits, LenID + 1);
    }

    RegSizeWords =
        PKA_WORD_SIZE_IN_32BIT_WORDS * ((opSizeInBits + SASI_PKA_WORD_SIZE_IN_BITS - 1) / SASI_PKA_WORD_SIZE_IN_BITS);

    /* ********************************************** */
    /*      check input parameters                   */
    /* ********************************************** */

    if (Opcode > PKA_MAX_OPCODE) {
        Error = PKA_ILLEGAL_OPCODE_ERROR;
        goto End;
    }

    if (LenID >= LEN_ID_MAX) {
        Error = PKA_ILLEGAL_OPERAND_LEN_ERROR;
        goto End;
    }

    if (IsAImmed > 1 || IsBImmed > 1 || ResDiscard > 1) {
        Error = PKA_ILLEGAL_OPERAND_TYPE_ERROR;
        goto End;
    }

    if ((OpA > 31) || (OpB > 31) || (Res > 31) || (Tag > 31)) {
        Error = PKA_ILLEGAL_OPERAND_ERROR;
        goto End;
    }

    /* for ModInv and Div operation check, that modulus or divider are not 0 */
    if (Opcode == PKA_OPCODE_ID_MODINV || Opcode == PKA_OPCODE_ID_DIVISION) {
        int8_t OpT; /* number of register to test its Value = 0 */

        /* Set OpT: 0 - for ModInv, OpB - for Div */
        if (Opcode == PKA_OPCODE_ID_MODINV) {
            Error = PKA_MODULUS_IS_NULL_ERROR;
            OpT   = 0;
        } else {
            Error = PKA_DIVIDER_IS_NULL_ERROR;
            OpT   = OpB;
        }

        /* Create full opcode word for add immediate 0 operation */
        FullOpCode = PKA_FullOpCode(PKA_OPCODE_ID_ADD, LenID, 0 /* isAImmed */, OpT /* N */, 1, 0 /* imm 0 */,
                                    1 /* ResDiscard */, 0 /* dumm */, Tag);

        /* write full opcode into PKA OPCODE register */
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, OPCODE), FullOpCode);

        /* test zero bit of STATUS register */
        PKA_GET_StatusAluOutZero(status);
        if (status == 1)
            goto End;
        else
            Error = SaSi_OK;
    }

    /* for ModInv operation check, that OpB is odd, else return Error (can't calculate,
       the user must use other function) */
    if (Opcode == PKA_OPCODE_ID_MODINV) {
        /* Create full opcode word for Test bit 0 operation */
        FullOpCode = PKA_FullOpCode(PKA_OPCODE_ID_AND, LenID, 0 /* isAImmed */, 0 /* N */, 1, 1 /* imm 1 */, 1 /* ResDiscard */,
                                    0 /* dumm */, Tag);

        /* write full opcode into PKA OPCODE register */
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, OPCODE), FullOpCode);

        /* test zero bit of STATUS register */
        PKA_GET_StatusAluOutZero(status);

        if (status == 1) {
            Error = PKA_MOD_EVEN_USE_OTHER_FUNC_ERROR;
            goto End;
        }
    }

    /* ********************************************** */
    /*      main PKI operation of this function      */
    /* ********************************************** */

    FullOpCode = PKA_FullOpCode(Opcode, LenID, IsAImmed, OpA, IsBImmed, OpB, ResDiscard, Res, Tag);
    PKA_WAIT_ON_PKA_PIPE_READY();
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, OPCODE), FullOpCode);

    /* ********************************************** */
    /* finishing operations for different cases      */
    /* ********************************************** */
    if (Opcode == PKA_OPCODE_ID_DIVISION) {
        /* for Div operation check, that OpB != 0, else return Error */
        PKA_GET_StatusDivByZero(status);
        if (status == 1) {
            Error = PKA_DIVIDER_IS_NULL_ERROR;
            goto End;
        }
    }

    /* wait for PKA done bit */
    PKA_WAIT_ON_PKA_DONE();

    /* if operation Tag = Print, then copy result into tempRes buffer */
    if (1 /* Tag == PKA_TAG_DebugPtint */ && ResDiscard == 0 && Opcode != PKA_OPCODE_ID_TERMINATE &&
        Opcode != PKA_OPCODE_ID_SEPINT) {
        SaSi_PalMemSetZero(tempRes, sizeof(tempRes));
        PKA_CopyDataFromPkaReg(tempRes /* dst_ptr */, RegSizeWords, Res /* srcReg */);

        if (Opcode == PKA_OPCODE_ID_DIVISION || Opcode == PKA_OPCODE_ID_MODINV) {
            if (Opcode == PKA_OPCODE_ID_DIVISION)
                OpPrint = OpA;
            else
                OpPrint = OpB;

            PKA_CopyDataFromPkaReg(tempRes1 /* dst_ptr */, RegSizeWords, OpPrint /* srcReg */);
        }
    }

/* End of function */
End:

    return Error;

} /* END OF function _PKA_ExecOperation */

#endif /* #if PKA_EXEC_OP_DEBUG */
