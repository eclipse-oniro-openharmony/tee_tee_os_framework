/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef PKA_EXPORT_H
#define PKA_EXPORT_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */

#include "ssi_pal_types.h"
#include "pka_dbg.h"
#include "sasi_error.h"
#include "pka_hw_defs.h"
#include "sasi_pka_defs_hw.h"

#ifdef __cplusplus
extern "C" {
#endif

/* internal ECPKI buffer structure used on LLF and containing Barrett tags for*
 *  modulus and gen.order                                                      */
typedef struct {
    uint32_t modTag[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];
    uint32_t ordTag[SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];
} PKA_EcDomainLlf_t;

/* **********      PKA_SetRegsSizesTab function      ******************** */
/*
 * @brief This function initializes the PKA registers sizes table.
 *
 *      The function sets sizes table as follows:
 *            -  tab[0] = MaxSizeBits; //maximal size, usually this is exact modulus size in bits
 *            -  tab[1] = Extended size with extra bits, aligned to big words.
 *            -  other entries = PKA_SIZE_ENTRY_NOT_USED, means - not used.
 *
 * @param[in] opSizeInBits - Size of PKA operations (modulus) in bits. The value must be in interval
 *                          from defined Min. to Max. size bits.
 * @param[in] regSizeInPkaWords - Sise of registers in PKA big words (e.g. 128-bit words).
 *
 * @return - no return value
 *
 */
void PKA_SetRegsSizesTab(uint32_t opSizeInBits, int32_t regSizeInPkaWords);

/* **********      PKA_InitPka function      ******************** */
/*
 * @brief This function initializes the PKA engine.
 *
 *    The function performs the following:
 *      - enables PKA clocks,
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
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure an error code:
 *                       PKA_REGISTER_SIZES_ERROR
 *                       PKA_ENTRIES_COUNT_ERROR
 *                       PKA_NOT_ENOUGH_MEMORY_ERROR
 *
 */
SaSiError_t PKA_InitPka(uint32_t opSizeInBits,      /* in */
                        uint32_t regSizeInPkaWords, /* in */
                        uint32_t *pRegsCount);      /* out */

/*
 * @brief These macros calls the PKA_InitPka function with appropriate
 *        parametr for different PKI algorithms.
 *
 */
#define PKA_InitPkaDefault(opSizeInBits) PKA_InitPka((opSizeInBits), 0 /* sizeInWords */, NULL /* (pRegsCount) */)

/* **********      PKA_FinishPKA function      ******************** */
/*
 * @brief This function ends the PKA engine session and disables PKA clocks.
 *
 *
 * @return - no return parameters.
 *
 */
void PKA_FinishPka(void);

/* **************************************************************************** */
/* ***********    LLF PKI PKA mathmatic functions and macros     ************** */
/* **************************************************************************** */

/*
 * The function initialize PKA and calculates the Barrett tag Np.
 *
 *  For RSA use truncated sizes:
 *      Np = truncated(2^(3*A+3*X-1) / ceiling(n/(2^(N-2*A-2*X)));
 *  For ECC - full sizes of arguments:
 *      Np = truncated(2^(N+A+X-1) / n);
 *
 * @author reuvenl (5/1/2014)
 *
 * @param [out] pNp - The pointer to the Barrett tag Np buffer. If pNp = Null,
 *        the function writes the calculated Np into PKA reg 1.
 * @param [in] pN - The pointer to the modulus n. If pN = Null,
 *        the function reads N from PKA reg 0.
 * @param [in] sizeNbits - The exact size of the modulus.
 * @param [in] pkaRegBitsLenId - LEN ID indicating the operation size in PKA register bits
 *
 * @return  - no return value
 */
SaSiError_t PKA_CalcNp(uint32_t *pNp, uint32_t *pN, uint32_t sizeNbits);

SaSiError_t PKA_CalcNpIntoPkaReg(uint32_t LenID, uint32_t sizeNbits, int8_t regN, int8_t regNp, int8_t regTemp1,
                                 int8_t regTempN);

/* if you want to execute operation using function defined in pka_dbg.c,
 then change the define of PKA_EXEC_OP_DEBUG to 1, else define it as empty.
 Make sure the library is compiled with flag DEBUG=1, so pka_dbg.c exists in library */

#define PKA_EXEC_OP_DEBUG 0
#if (PKA_EXEC_OP_DEBUG && defined PKA_DEBUG && defined DEBUG)
SaSiError_t _PKA_ExecOperation(uint32_t Opcode,     /* in */
                               uint32_t LenID,      /* in */
                               uint32_t IsAImmed,   /* in */
                               uint32_t OpA,        /* in */
                               uint32_t IsBImmed,   /* in */
                               uint32_t OpB,        /* in */
                               uint32_t ResDiscard, /* in */
                               uint32_t Res,        /* in */
                               uint32_t Tag /* in */);

#else // used in ExecOperation debug mode
#define _PKA_ExecOperation(Opcode, LenID, IsAImmed, OpA, IsBImmed, OpB, ResDiscard, Res, Tag)                    \
    {                                                                                                            \
        uint32_t fullOpCode;                                                                                     \
        fullOpCode =                                                                                             \
            PKA_FullOpCode((Opcode), (LenID), (IsAImmed), (OpA), (IsBImmed), (OpB), (ResDiscard), (Res), (Tag)); \
        PKA_WAIT_ON_PKA_PIPE_READY();                                                                            \
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, OPCODE), fullOpCode);                                \
    }

#endif

/* ********************************************************************** */
/* Macros for calling PKA operations (names according to operation issue */
/* ********************************************************************** */

/* ---------------------------------- */
/*   1.  ADD - SUBTRACT operations  */
/* ---------------------------------- */
/*  Add:   Res =  OpA + OpB  */
#define PKA_ADD(LenID, Res, OpA, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_ADD, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  AddIm:  Res =  OpA + OpBIm  */
#define PKA_ADD_IM(LenID, Res, OpA, OpBIm) \
    _PKA_ExecOperation(PKA_OPCODE_ID_ADD, (LenID), 0, (OpA), 1, (OpBIm), 0, (Res), 0)
/*  Sub:  Res =  OpA - OpB  */
#define PKA_SUB(LenID, Res, OpA, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_SUB, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  SubIm:  Res =  OpA - OpBIm  */
#define PKA_SUB_IM(LenID, Res, OpA, OpBIm) \
    _PKA_ExecOperation(PKA_OPCODE_ID_SUB, (LenID), 0, (OpA), 1, (OpBIm), 0, (Res), 0)
/*  Neg:  Res =  0 - OpB  */
#define PKA_NEG(LenID, Res, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_SUB, (LenID), 1, 0, 0, (OpB), 0, (Res), 0)
/*  ModAdd:  Res =  (OpA + OpB) mod N  */
#define PKA_MOD_ADD(LenID, Res, OpA, OpB) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MODADD, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  ModAddIm:  Res =  (OpA + OpBIm) mod N  */
#define PKA_MOD_ADD_IM(LenID, Res, OpA, OpBIm) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MODADD, (LenID), 0, (OpA), 1, (OpBIm), 0, (Res), 0)
/*  ModSub:  Res =  (OpA - OpB) mod N  */
#define PKA_MOD_SUB(LenID, Res, OpA, OpB) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MODSUB, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  ModSubIm:  Res =  (OpA - OpBIm) mod N  */
#define PKA_MOD_SUB_IM(LenID, Res, OpA, OpBIm) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MODSUB, (LenID), 0, (OpA), 1, (OpBIm), 0, (Res), 0)
/*  ModNeg:  Res =  (0 - OpB) mod N  */
#define PKA_MOD_NEG(LenID, Res, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_MODSUB, (LenID), 1, 0, 0, (OpB), 0, (Res), 0)

/* ---------------------------------- */
/*   2.  Logical   operations       */
/* ---------------------------------- */

/*  AND:  Res =  OpA & OpB  */
#define PKA_AND(LenID, Res, OpA, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_AND, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  AndIm:  Res =  OpA & OpB  */
#define PKA_AND_IM(LenID, Res, OpA, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_AND, (LenID), 0, (OpA), 1, (OpB), 0, (Res), 0)
/*  Tst0:  OpA & 0x1 -  tests the bit 0 of operand A. If bit0 = 0, then ZeroOfStatus = 1, else 0  */
#define PKA_TEST_BIT0(LenID, OpA) _PKA_ExecOperation(PKA_OPCODE_ID_AND, (LenID), 0, (OpA), 1, 0x01, 1, RES_DISCARD, 0)
/*  TstBit:  OpA & (1<<i) -  tests the bit i of operand A. If biti = 0, then ZeroOfStatus = 1, else 0  */
#define PKA_TEST_BIT(LenID, OpA, i) \
    _PKA_ExecOperation(PKA_OPCODE_ID_AND, (LenID), 0, (OpA), 1, 0x01 << (i), 1, RES_DISCARD, 0)
/*  Clr0:  Res =  OpA & (-2)  - clears the bit 0 of operand A.  Note:  -2 = 0x1E  for 5-bit size */
#define PKA_CLEAR_BIT0(LenID, Res, OpA) _PKA_ExecOperation(PKA_OPCODE_ID_AND, (LenID), 0, (OpA), 1, 0x1E, 0, (Res), 0)
/*  Clr:  Res =  OpA & 0  - clears the operand A.  */
#define PKA_CLEAR(LenID, OpA) _PKA_ExecOperation(PKA_OPCODE_ID_AND, (LenID), 0, (OpA), 1, 0x00, 0, (OpA), 0)
/*  Clear:  for full clearing the actual register opA, this macro calls Clr operation twice.  */
#define PKA_2CLEAR(LenID, OpA) \
    PKA_CLEAR(LenID, OpA);     \
    PKA_CLEAR(LenID, OpA)
/*  OR:  Res =  OpA || OpB  */
#define PKA_OR(LenID, Res, OpA, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_OR, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  OrIm:  Res =  OpA || OpB  */
#define PKA_OR_IM(LenID, Res, OpA, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_OR, (LenID), 0, (OpA), 1, (OpB), 0, (Res), 0)
/*  Copy:  OpDest =  OpSrc || 0  */
#define PKA_COPY(LenID, OpDest, OpSrc) \
    _PKA_ExecOperation(PKA_OPCODE_ID_OR, (LenID), 0, (OpSrc), 1, 0x00, 0, (OpDest), 0)
/*  Set0:  Res =  OpA || 1  : set bit0 = 1, other bits are not changed */
#define PKA_SET_BIT0(LenID, Res, OpA) _PKA_ExecOperation(PKA_OPCODE_ID_OR, (LenID), 0, (OpA), 1, 0x01, 0, (Res), 0)
/*  Xor:  Res =  OpA ^ OpB  */
#define PKA_XOR(LenID, Res, OpA, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_XOR, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  XorIm:  Res =  OpA ^ OpB  */
#define PKA_XOR_IM(LenID, Res, OpA, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_XOR, (LenID), 0, (OpA), 1, (OpB), 0, (Res), 0)
/*  Flip0:  OpA =  OpA || 1  - inverts the bit 0 of operand A  */
#define PKA_FLIP_BIT0(LenID, Res, OpA) _PKA_ExecOperation(PKA_OPCODE_ID_XOR, (LenID), 0, (OpA), 1, 0x01, 0, (Res), 0)
/*  Invert:  Res =  OpA ^ 0xFFF.FF  :  inverts all bits of OpA .
                    Note: 0xFFFFF =  0x1F for 5 bits size of second operand */
#define PKA_INVERT_BITS(LenID, Res, OpA) _PKA_ExecOperation(PKA_OPCODE_ID_XOR, (LenID), 0, (OpA), 1, 0x1F, 0, (Res), 0)
/*  Compare:  OpA ^ OpB . Rsult of compare in ZeroBitOfStatus:  If OpA == OpB then Z = 1 */
#define PKA_COMPARE(LenID, OpA, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_XOR, (LenID), 0, (OpA), 0, (OpB), 1, (0), 0)
/*  CompareImmediate:  OpA ^ OpB . Rsult of compare in ZeroBitOfStatus:  If OpA == OpB then status Z = 1 */
#define PKA_COMPARE_IM(LenID, OpA, OpBim) \
    _PKA_ExecOperation(PKA_OPCODE_ID_XOR, (LenID), 0, (OpA), 1, (OpBim), 1, (0), 0)

/* ---------------------------------- */
/*   3.  SHIFT    operations        */
/* ---------------------------------- */

/*  SHR0:  Res =  OpA >> (S+1) :   shifts right operand A by S+1 bits, insert 0 to left most bits */
#define PKA_SHR_FILL0(LenID, Res, OpA, S) _PKA_ExecOperation(PKA_OPCODE_ID_SHR0, (LenID), 0, (OpA), 0, (S), 0, (Res), 0)
/*  SHR1:  Res =  OpA >> (S+1) :   shifts right operand A by S+1 bits, insert 1 to left most bits */
#define PKA_SHR_FILL1(LenID, OpA, S, Res) _PKA_ExecOperation(PKA_OPCODE_ID_SHR1, (LenID), 0, (OpA), 0, (S), 0, (Res), 0)
/*  SHL0:  Res =  OpA << (S+1) :   shifts left operand A by S+1 bits, insert 0 to right most bits */
#define PKA_SHL_FILL0(LenID, Res, OpA, S) _PKA_ExecOperation(PKA_OPCODE_ID_SHL0, (LenID), 0, (OpA), 0, (S), 0, (Res), 0)
/*  SHL1:  Res =  OpA << (S+1) :   shifts left operand A by S+1 bits, insert 1 to right most bits */
#define PKA_SHL_FILL1(LenID, OpA, S, Res) _PKA_ExecOperation(PKA_OPCODE_ID_SHL1, (LenID), 0, (OpA), 0, (S), 0, (Res), 0)

/* ----------------------------------------------------- */
/*   2.  Multiplication and other   operations         */
/*       Note:  See notes to PKA_ExecOperation */
/* ----------------------------------------------------- */

/*  RMul:  Res =  LowHalfOf(OpA * OpB), where size of operands and result is equaled to operation
           size, defined by LenID. Note: for receiving full result, the LenID must be set according
           to (sizeA + sizeB) and leading not significant bits of operands must be zeroed */
#define PKA_MUL_LOW(LenID, Res, OpA, OpB) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MULLOW, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  HMul:  Res =  HighHalfOf(OpA * OpB) + one high word of low half of (OpA * OpB), where size of
           operands is equaled to operation size, defined by LenID. Note: Size of operation result
           is by one word large, than operation size */
#define PKA_MUL_HIGH(LenID, Res, OpA, OpB) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MULHIGH, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  ModMul:  Res =  OpA * OpB  mod N - modular multiplication */
#define PKA_MOD_MUL(LenID, Res, OpA, OpB) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MODMUL, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  ModMulN:  Res =  OpA * OpB  mod N - modular multiplication (final reduction is omitted)*
 *   up to PKA_EXTRA_BITS extra bits                                  */
#define PKA_MOD_MUL_NFR(LenID, Res, OpA, OpB) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MODMULN, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  ModMulAcc:  Res =  OpA * OpB + OpC mod N - modular multiplication and     *
 *   adding, result reduced                                */
#define PKA_MOD_MUL_ACC(LenID, Res, OpA, OpB, OpC) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MODMLAC, (LenID), 0, (OpA), 0, (OpB), 0, (Res), (OpC))
/*  ModMulAccN:  Res =  OpA * OpB + OpC mod N - modular multiplication and    *
 *   acdding (final reduction is omitted) -  up to PKA_EXTRA_BITS extra bits                        */
#define PKA_MOD_MUL_ACC_NFR(LenID, Res, OpA, OpB, OpC) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MODMLACNR, (LenID), 0, (OpA), 0, (OpB), 0, (Res), (OpC))
/*  ModExp:  Res =  OpA ** OpB  mod N - modular exponentiation */
#define PKA_MOD_EXP(LenID, Res, OpA, OpB) \
    _PKA_ExecOperation(PKA_OPCODE_ID_MODEXP, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  Divide:  Res =  OpA / OpB , OpA = OpA mod OpB - division,  */
#define PKA_DIV(LenID, Res, OpA, OpB) \
    _PKA_ExecOperation(PKA_OPCODE_ID_DIVISION, (LenID), 0, (OpA), 0, (OpB), 0, (Res), 0)
/*  ModInv:  Modular inversion: calculates   Res = 1/OpB mod N  */
#define PKA_MOD_INV(LenID, Res, OpB) _PKA_ExecOperation(PKA_OPCODE_ID_MODINV, (LenID), 1, 1, 0, (OpB), 0, (Res), 0)
/* Modular reduction: Res = OpB mod B  by subtract the modulus B     *
 *   times, while Res > B. Counter C should be set in the Tag bits of Status   */
#define PKA_REDUCE(LenID, Res, OpA) \
    _PKA_ExecOperation(PKA_OPCODE_ID_REDUCTION, (LenID), 0, (OpA), 0, 0 /* opB not need */, 0, (Res), 0 /* Tag */)

/* ************************************************
 * *************  second Level macros ************
 * *********************************************** */

/* mod inversion using exponentiation, used when 'a' can be even number, but *
 *  runs at constant time                                                     */
#define PKA_MOD_INV_W_EXP(res, a, nm2)                        \
    {                                                         \
        PKA_SUB_IM(LEN_ID_N_PKA_REG_BITS, (nm2), 0 /* n */, 2); \
        PKA_MOD_EXP(LEN_ID_N_BITS, (res), (a), (nm2));        \
    }

#define PKA_SET_VAL(a, v)                           \
    {                                               \
        PKA_AND_IM(LEN_ID_N_PKA_REG_BITS, a, a, 0); \
        PKA_OR_IM(LEN_ID_N_PKA_REG_BITS, a, a, v);  \
    }

#define PKA_COMPARE_STATUS(LenId, a, b, stat) \
    {                                         \
        PKA_COMPARE(LenId, a, b);             \
        PKA_GET_StatusAluOutZero(stat);       \
    }

#define PKA_COMPARE_IM_STATUS(LenId, a, b, stat) \
    {                                            \
        PKA_COMPARE_IM(LenId, a, b);             \
        PKA_GET_StatusAluOutZero(stat);          \
    }

#define PKA_READ_BIT0(LenId, reg, bitVal) \
    {                                     \
        PKA_TEST_BIT0(LenId, reg);        \
        PKA_GET_StatusAluOutZero(bitVal); \
        (bitVal) = !(bitVal);             \
    }

/* uint32 b - bit i value, i-num. of LS bit, i <= 31 */
#define PKA_READ_BIT(bitVal, reg, i)            \
    {                                           \
        PKA_TEST_BIT(1 /* lenId */, reg, (i), 0); \
        PKA_GET_StatusAluOutZero((bitVal));     \
        (bitVal) = !(bitVal);                   \
    }

#define PKA_READ_WORD_FROM_REG(Val, i, VirtReg)          \
    {                                                    \
        uint32_t Addr;                                   \
        PKA_GetRegAddress(VirtReg, Addr);                \
        PKA_HW_READ_VALUE_FROM_PKA_MEM(Addr + (i), Val); \
    }

#define PKA_WRITE_WORD_TO_REG(Val, i, VirtReg)           \
    {                                                    \
        uint32_t addr;                                   \
        PKA_GetRegAddress((VirtReg), addr);              \
        PKA_HW_LOAD_VALUE_TO_PKA_MEM(addr + (i), (Val)); \
    }

/* *******************     PKA_ExecFullModInv    ********************** */
/*
 * @brief This function calculates modular inversion Res = 1/B mod N for both odd and even modulus.
 *
 *        The function works with virtual pointers to PKA registers (sequence numbers)
 *        and does the following:
 *
 *        1. Checks the parity of modulus N (in register 0) and operand B. If they both are even,
 *           returns an Error (inverse is not exist)
 *        2. If the modulus is odd, then calls the PKA_MOD_INV function for calculating
 *           the inverse.
 *        3. If the modulus is even, then the function performs the following:
 *           3.1  Saves modulus N: rT0<=N;
 *           3.2. Sets B into reg N: N<=B.
 *           3.3. Res = N^-1 mod B (call PKA_MOD_INV ); Restore mod: N<=rT0;
 *           3.4. rT0 = high(N*N^-1) = PKA_MUL_HIGH(N,Res,rT0);
 *           3.5. Shift right rT0 >> 32;
 *           3.6. rT1 = low(N*N^-1) = PKA_MUL_LOW(N,Res,rT1);
 *           3.7. Res = rT0 / B : call PKA_LongDiv(rT0,B,Res);
 *           3.7. rT0 = rT1 / B : call PKA_DIV(rT1,B,rT0);
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
 *                       PKA_ILLEGAL_OPCODE_ERROR
 *                       PKA_ILLEGAL_OPERAND_LEN_ERROR
 *                       PKA_ILLEGAL_OPERAND_TYPE_ERROR
 *                       PKA_ILLEGAL_OPERAND_ERROR
 *                       PKA_INVERSION_NOT_EXISTS_ERROR
 *
 */
SaSiError_t PKA_ExecFullModInv(int8_t OpB, /* in */
                               int8_t Res, /* in */
                               int8_t rT0, /* in */
                               int8_t rT1, /* in */
                               int8_t rT2, /* in */
                               int8_t rT3 /* in */);

/* ******************************************************************************************** */
/* ******************************************************************************************** */
/*                                                                                             */
/*                FUNCTIONS PERFORMING ALGORITHMS and USED IN PKI                              */
/*                                                                                             */
/* ******************************************************************************************** */
/* ******************************************************************************************** */

/* ***************************************************************************** */
/* ************   Auxiliary functions used in PKA               **************** */
/* ***************************************************************************** */

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
                          uint32_t LenID /* in */);

void PKA_ClearPkaRegWords(uint32_t dstReg, /* out */
                          uint32_t sizeWords /* in */);

/* **********      PKA_CopyDataIntoPkaReg function      ******************** */
/*
 * @brief This function  copies source data into PKA register .
 *
 *        Assumings: - PKA is initialized.
 *                   - Length of extended (by word) registers is placed into LenID entry of
 *                     sizes table.
 *                   - If the extra word of register must be cleared then the user must
 *                     set LenID according to extended register size.
 *
 * @param[in] dstReg       - Virtual address (number) of destination register.
 * @param[in] LenId        - ID of entry of regsSizesTable defines registers length with word extension.
 * @param[in] src_ptr      - Pointer to source buffer.
 * @param[in] sizeWords    - Data size in Words.
 *
 * @return - no return parameters.
 *
 */
void PKA_CopyDataIntoPkaReg(uint32_t dstReg,         /* out */
                            uint32_t LenID,          /* in */
                            const uint32_t *src_ptr, /* in */
                            uint32_t sizeWords /* in */);

/* **********      PKA_CopyDataFromPkaReg      ******************** */
/*
 * @brief This function copies data from PKA register into output buffer .
 *
 *        Assumings: - PKA is initialized.
 *                   - Length of extended (by word) registers is placed into LenID entry of
 *                     sizes table.
 *                   - If the extra word of register must be cleared, then the user must
 *                     set LenID according to extended register size.
 *
 * @param[in] dst_ptr      - Pointer to destination buffer.
 * @param[in] sizeWords - Source size in Words.
 * @param[in] srcReg       - Virtual address (number) of source PKA register.
 *
 * @return - no return parameters.
 *
 */
void PKA_CopyDataFromPkaReg(uint32_t *dst_ptr,  /* out */
                            uint32_t sizeWords, /* in */
                            uint32_t srcReg /* in */);

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
uint32_t PKA_GetRegEffectiveSizeInBits(uint32_t reg /* in */);

/*
 * The function returns result (x == y mod n).
 * Assumed: n - in reg. 0, lenId = 1.
 *
 * @author reuvenl (6/20/2014)
 *
 * @param rX - first reg.
 * @param rY - second reg.
 * @param tt1, tt2 - temp PKA regs.
 * @param pRegs - pointer to regs bit-list.
 *
 * @return bool
 */
bool pka_mod_equal(uint32_t rX, uint32_t rY, uint32_t tt1, uint32_t tt2);

#ifdef __cplusplus
}
#endif

#endif
