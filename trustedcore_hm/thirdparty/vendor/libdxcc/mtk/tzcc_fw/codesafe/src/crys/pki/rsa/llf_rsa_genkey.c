/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

#include "ssi_pal_types.h"
#include "sasi_rsa_types.h"
#include "sasi_rsa_error.h"
#include "sasi_rsa_local.h"
#include "sasi_common_math.h"
#include "sasi_rnd.h"
#include "sasi_rnd_error.h"
#include "pka.h"
#include "pka_export.h"
#include "pka_hw_defs.h"
#include "ssi_pal_mem.h"
#include "llf_rsa_public.h"
#include "llf_rsa.h"

/* *********************** Defines **************************** */

/* canceling the lint warning:
Info 716: while(1) ... */

/* canceling the lint warning: Constant value Boolean
Warning 506 regarding while(1) ... */


/* canceling the lint warning:
Info 506: Constant value Boolean ... */


/* canceling the lint warning:
Info 774: Boolean within 'if' always evaluates to False */


/* ..................... PRIME1 definitions ........................ */

#define LLF_PKI_KG_X931_PRIME1_SIZE_IN_BITS        101
#define LLF_PKI_KG_X931_PRIME1_SIZE_IN_32BIT_WORDS (CALC_FULL_32BIT_WORDS(LLF_PKI_KG_X931_PRIME1_SIZE_IN_BITS))
#define LLF_PKI_KG_X931_PRIME1_SIZE_IN_8BIT_WORDS  (CALC_FULL_BYTES(LLF_PKI_KG_X931_PRIME1_SIZE_IN_BITS))

#define LLF_PKI_QUICK_PRIME_TEST_DIVISIONS_COUNT 128
/* if the number of Rabin-Miller tests in RSA key generation */
#define LLF_PKI_KG_X931_RABIN_TESTS_FOR_101_255_BITS    27
#define LLF_PKI_KG_X931_RABIN_TESTS_FOR_256_511_BITS    15
#define LLF_PKI_KG_X931_RABIN_TESTS_FOR_512_1023_BITS   8
#define LLF_PKI_KG_X931_RABIN_TESTS_FOR_GREAT_1023_BITS 4

#define CALC_PRIME_PRODUCT_NUM \
    (SaSi_MIN(CALC_FULL_32BIT_WORDS(SaSi_RSA_MAX_KEY_GENERATION_SIZE_BITS), SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS))
#define PRIME_PRODUCT_BUFF_SIZE \
    (SaSi_MAX(CALC_FULL_32BIT_WORDS(SaSi_RSA_MAX_KEY_GENERATION_SIZE_BITS), SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS))
#define PRIME_NUM 256

#define CALC_PRIME_PRODUCT (CALC_PRIME_PRODUCT_NUM / 2 - 3)

#if ((SaSi_PKA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS - 6) < CALC_PRIME_PRODUCT)
#error("(SaSi_PKA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS-6) < CALC_PRIME_PRODUCT")
#endif

/* *************************** Enums ****************************** */

/* *********************** Global Data **************************** */

extern const int8_t regTemps[PKA_MAX_COUNT_OF_PHYS_MEM_REGS];

const uint32_t g_PrimeProduct[PRIME_PRODUCT_BUFF_SIZE] = {
    3234846615UL, 95041567UL,   907383479,    4132280413UL, 121330189,    257557397UL,  490995677,    842952707,
    1314423991UL, 2125525169UL, 3073309843UL, 16965341,     20193023,     23300239,     29884301,     35360399,
    42749359UL,   49143869,     56466073,     65111573,     76027969,     84208541,     94593973,     103569859,
    119319383,    133390067UL,  154769821UL,  178433279,    193397129,    213479407,    229580147,    250367549,
    271661713,    293158127,    319512181,    357349471UL,  393806449,    422400701,    452366557,    507436351,
    547978913,    575204137,    627947039,    666785731,    710381447UL,  777767161UL,  834985999UL,  894826021UL,
    951747481UL,  1019050649UL, 1072651369UL, 1125878063UL, 1185362993UL, 1267745273UL, 1322520163UL, 1391119619UL,
    1498299287UL, 1608372013UL, 1700725291UL, 1805418283UL, 1871456063UL, 2008071007UL, 2115193573UL, 2178429527UL,
    2246284699UL, 2385788087UL
};

const uint16_t g_SmallPrime[PRIME_NUM] = {
    3,    5,    7,    11,   13,   17,   19,   23,   29,   31,   37,   41,   43,   47,   53,   59,   61,   67,   71,
    73,   79,   83,   89,   97,   101,  103,  107,  109,  113,  127,  131,  137,  139,  149,  151,  157,  163,  167,
    173,  179,  181,  191,  193,  197,  199,  211,  223,  227,  229,  233,  239,  241,  251,  257,  263,  269,  271,
    277,  281,  283,  293,  307,  311,  313,  317,  331,  337,  347,  349,  353,  359,  367,  373,  379,  383,  389,
    397,  401,  409,  419,  421,  431,  433,  439,  443,  449,  457,  461,  463,  467,  479,  487,  491,  499,  503,
    509,  521,  523,  541,  547,  557,  563,  569,  571,  577,  587,  593,  599,  601,  607,  613,  617,  619,  631,
    641,  643,  647,  653,  659,  661,  673,  677,  683,  691,  701,  709,  719,  727,  733,  739,  743,  751,  757,
    761,  769,  773,  787,  797,  809,  811,  821,  823,  827,  829,  839,  853,  857,  859,  863,  877,  881,  883,
    887,  907,  911,  919,  929,  937,  941,  947,  953,  967,  971,  977,  983,  991,  997,  1009, 1013, 1019, 1021,
    1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291,
    1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447,
    1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571,
    1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621
};

const uint16_t g_LastProductPrime[PRIME_PRODUCT_BUFF_SIZE] = {
    9,   14,  19,  24,  28,  32,  36,  40,  44,  48,  52,  55,  58,  61,  64,  67,  70,  73,  76,  79,  82,  85,
    88,  91,  94,  97,  100, 103, 106, 109, 112, 115, 118, 121, 124, 127, 130, 133, 136, 139, 142, 145, 148, 151,
    154, 157, 160, 163, 166, 169, 172, 175, 178, 181, 184, 187, 190, 193, 196, 199, 202, 205, 208, 211, 214, 217

};

/* ----------------------------------------------------------------------- */

#if defined LLF_PKI_PKA_DEBUG && defined DEBUG
#if (defined RSA_KG_NO_RND || defined RSA_KG_FIND_BAD_RND)
uint8_t PQindex;
/* for debug goals */
/* for Q */
/* P3 big end 1E05B8F18D807DB7A47EF53567 nearest random is: 1E 05 B8 F1 8D 80 7D B7 A4 7E F5 35 99 */
uint8_t rBuff3[16] = {
    /* 0xFB,0xD4,0xD3,0x19,0xA8,0x6B,0x7C,0x8C,0x80,0x6D,0x66,0xB2,0x1C */
    /* 0xC3,0xB6,0x75,0xA3,0x29,0x20,0xFB,0x37,0x1F,0x86,0xD7,0xBE,0x19 */
    0x67, 0x35, 0xF5, 0x7E, 0xA4, 0xB7, 0x7D, 0x80, 0x8D, 0xF1, 0xB8, 0x05, 0x1E
};
/* P4 big end 1E05B8F18D807DB7A47EF5359A nearest random is: 1E 05 B8 F1 8D 80 7D B7 A4 7E F5 35 A7 */
uint8_t rBuff4[16] = {
    /* 0x29,0x18,0x50,0x8B,0x32,0x12,0x2E,0x56,0x2C,0x35,0x6D,0x6F,0x1F */
    /* 0x07,0x77,0xC3,0x08,0x45,0xEB,0x47,0xC1,0x7F,0xED,0x79,0xB6,0x1D */
    0x9A, 0x35, 0xF5, 0x7E, 0xA4, 0xB7, 0x7D, 0x80, 0x8D, 0xF1, 0xB8, 0x05, 0x1E
};

/* for P */
/* P1 big end 1E05B8F18D807DB7A47EF52563 nearest random is: 1E05B8F18D807DB7A47EF52563 */
uint8_t rBuff1[16] = {
    /* 0xF1,0x20,0x85,0xD2,0x95,0xC8,0x61,0x3F,0x93,0x03,0x24,0xB2,0x1A */
    /* 0xEF,0xA7,0x21,0x4E,0x4B,0x49,0x60,0x2E,0xC5,0x7D,0x1B,0x83,0x17 */
    0x63, 0x25, 0xF5, 0x7E, 0xA4, 0xB7, 0x7D, 0x80, 0x8D, 0xF1, 0xB8, 0x05, 0x1E
};
/* P2 big end 1E05B8F18D807DB7A47EF51595 nearest random is: 1E05B8F18D807DB7A47EF515A1 */
uint8_t rBuff2[16] = {
    /* 0xB5,0xE5,0x1E,0x07,0x67,0xBC,0xB0,0xB9,0xAC,0xA6,0x69,0x03,0x17 */
    /* 0x4B,0xA5,0x0C,0x16,0x68,0x86,0x0F,0x1C,0xAF,0x43,0xDB,0xE3,0x19 */
    0x95, 0x15, 0xF5, 0x7E, 0xA4, 0xB7, 0x7D, 0x80, 0x8D, 0xF1, 0xB8, 0x05, 0x1E
};

/* temp buffers for output results of generation P1,P2 for P and Q  */
uint32_t P1pR[4], P2pR[4], P1qR[4], P2qR[4];
/* final values of P1,P2 for P and Q */
uint32_t P1pPr[4], P2pPr[4], P1qPr[4], P2qPr[4];
uint32_t *P1R_ptr, *P2R_ptr, *P1Pr_ptr, *P2Pr_ptr;

/* temp buffers and pointer for output the P,Q  after generation */
uint32_t rBuffP[64], rBuffQ[64];
uint32_t *PQ_ptr;
#endif
#endif

/* *********************** External functions **************************** */

extern SaSiError_t SaSi_RndGenerateWordsArrayInRange(SaSi_RND_Context_t *rndContext_ptr, uint32_t rndSizeInBits,
                                                     uint32_t *maxVect_ptr, uint32_t *rndVect_ptr, uint32_t *tmp_ptr);

/* ************************ Private functions **************************** */

/* ***************************************************************************************** */
/* @brief This function calculates Jacobi index .
 *
 * If there is such a vector b, that satisfies the condition b^2 = a mod p, the result is 1.
 * If there is no such vector, the result is -1.
 *
 * @param[in] LenId - the RegsSizesTable entry, containing the exact size of vector p in bits.
 * @param[in] rA - The virtual pointer to the base vector.
 * @param[in] rP - The virtual pointer to the prime to be tested (the modulos).
 * @param[out] JacRes_ptr - a pointer to the result var (1,0,-1) as described in the description.
 * @param[in] PrimeSizeInBits - The prime size in bits.
 *            operations on temp buffers.
 * @param[in] rA1, rP1, rT - virtual pointers to temp PKA registers.
 */
static SaSiError_t llfRsaKgX931Jacobi(uint32_t LenID,      /* in */
                                      int8_t rA,           /* in */
                                      int8_t rP,           /* in */
                                      int32_t *JacRes_ptr, /* out */
                                      int8_t rA1,          /* temp reg */
                                      int8_t rP1,          /* temp reg */
                                      int8_t rT)
{
    /* FUNCTION DECLARATIONS */

    int32_t k, s;
    uint32_t residue;

    uint32_t bitVal;

    /* low words of A1 and P1 */
    uint32_t A1_0, P1_0;

    /* temp swap value */
    int8_t rSw;

    /* PKA status */
    uint32_t status;

    /* FUNCTION LOGIC */

    /* .......................... initialize local variables ............................... */
    /* ------------------------------------------------------------------------------------- */

    /* copy the input vectors with extension */
    PKA_COPY(LEN_ID_MAX_BITS, rA1 /* dest */, rA /* src */);
    PKA_COPY(LEN_ID_MAX_BITS, rP1 /* dest */, rP /* src */);

    /* initialize the result as 1 ( default ) */
    *JacRes_ptr = 1;

    /* ..................... if a is 1 return the result 1 ...................... */
    /* -------------------------------------------------------------------------- */

    /* step 3.  if a1 == 1, return - we have done */
    PKA_COMPARE_IM_STATUS(LenID + 1, rA1 /* OpA */, 1 /* OpB */, status);
    if (status == 1) {
        return SaSi_OK;
    }

    /* ..................... do loop for finding the jacobi ..................... */
    /* -------------------------------------------------------------------------- */

    do {
        /* Step 1.  If a == 0, return the result 0      */
        /* ---------------------------------------------- */
        PKA_COMPARE_IM_STATUS(LenID + 1, rA1 /* OpA */, 0 /* OpB */, status);
        if (status == 1) {
            *JacRes_ptr = 0;
            return SaSi_OK;
        }

        /* Step 2. Find out larger power of two for A1  */
        /* ---------------------------------------------- */

        k = 0;

        /* check parity of A1 */
        PKA_READ_BIT0(LenID + 1, rA1 /* OpA */, bitVal);
        while (bitVal == 0) {
            /* divide by 2 */
            PKA_SHR_FILL0(LenID + 1, rA1 /* Res */, rA1 /* OpA */, 1 - 1 /* S */);
            PKA_READ_BIT0(LenID + 1, rA1 /* OpA */, bitVal);
            k++;
        }

        /* get low bytes of A1 and P1                   */
        /* ---------------------------------------------- */
        PKA_READ_WORD_FROM_REG(A1_0, 0, rA1);
        PKA_READ_WORD_FROM_REG(P1_0, 0, rP1);

        /* initialize s as 0 */
        s = 0;

        /* step 3.  if k is even set s=1                */
        /* ---------------------------------------------- */
        if ((k & 1) == 0) {
            s = 1;
        } else {
            /* else set s=1 if p = 1 or 7 (mod 8) or s=-1 if p = 3 or 5 (mod 8) */
            residue = P1_0 & 7;

            if (residue == 1 || residue == 7) {
                s = 1;
            } else if (residue == 3 || residue == 5) {
                s = -1;
            }
        }

        /* Step 4.  If p == 3 (mod 4) *and* a1 == 3 (mod 4) then s = -s */
        /* -------------------------------------------------------------- */
        if (((P1_0 & 3) == 3) && ((A1_0 & 3) == 3)) {
            s = -s;
        }

        /* Step 5 : Update the result                   */
        *JacRes_ptr *= s;

        /* Step 6.  If a1 == 1, return - done           */
        /* ---------------------------------------------- */

        PKA_COMPARE_IM_STATUS(LenID + 1, rA1 /* OpA */, 1 /* OpB */, status);
        if (status == 1)
            return SaSi_OK;

        /* p1 = p1 mod a1 - the result is at rP1 register  */
        PKA_DIV(LenID + 1, rT /* ResNotUsed */, rP1 /* OpA */, rA1 /* OpB */);

        /* Step 7.  Exchange P1 & A1                    */
        /* ---------------------------------------------- */
        rSw = rP1;
        rP1 = rA1;
        rA1 = rSw;

    } while (1); /* end of do loop */

} /* END OF llfRsaKgX931Jacobi */

/* ******************************************************************************************** */
/*
 * @brief This function executes the rabin miller test according to the the ANS X9.31 standard.
 *
 *    Algorithm:
 *        1. Let: prime candidate P = 1 + 2^a * m, where: m is odd and a > 0.
 *        2. For( i = 0; i < countTests; i++ ) do
 *             2.1. Generate random number b in range  1 < b < P.
 *             2.2. Calculate z = b^m mod P.
 *             2.3. If z = 1, or z = P-1, then goto st.6.
 *             2.4. For(j = 1; j < a; j++ ) do
 *                   2.4.1.  set z = z^2 mod P
 *                   2.4.2. If  z = P-1, then goto st.6.
 *                   2.4.3. If  z = 1, then output "composite" and stop.
 *                  End for //2.4.
 *             2.5. Output "composite". Stop.
 *           End for //2.
 *        3. Output P is "probable prime". Stop.
 *
 *       Assumings: - PKA is initialised on default mode for prime P as modulus (see near);
 *                  - the registers sizes table and mapping table are set on default mode,
 *                    according to exact P size, that means:
 *                      -- registers sizes table entries are set by default as follows:
 *                           LenID - P_sizeBits, LenID+1 - (32*P_sizeWords + 32 bit);
 *                  - the prime candidate P is inserted in the modulus register PKA_REG_N;
 *                  - the Barrett tag NP for P is inserted into register 1;
 *                  - the PKA clocks are initialized.
 *
 *       NOTE: - The function uses 7 PKA data registers: PKA_REG_N,PKA_REG_NP,30,31, and 3 temp registers.
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param[in]  LenID - The ID of entry in RegsSizesTable, containing PSizeInBits.
 * @param[in]  PSizeInBits - The prime candidate size
 * @param[out] SuccessCode_ptr - the success code : 0 - the test failed , 1 the test passed.
 * @param[in]  testsCount - Count of exponentiations in test. If CountTests = 0, then
 *                          CountTests will be set automatically according to prime size, else the
 *                          function performs recieved count of tests.
 *                             operations on temp buffers.
 * @param[in]  rT0,rT1,rT2 - virtual pointers to temp registers,
 * @param[in]  temp_ptr - pointer to temp buffer of size (2*PSizeInBits/8) bytes.
 *
 * assumptions : the max size supported is 2112 bits.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
static SaSiError_t llfRsaKgX931MillerRabinTest(SaSi_RND_Context_t *rndContext_ptr, uint32_t LenID, /* in */
                                               uint32_t PSizeInBits,                               /* in */
                                               int8_t *SuccessCode_ptr,                            /* out */
                                               uint8_t testsCount,                                 /* in */
                                               int8_t rT0,                                         /* temp registers */
                                               int8_t rT1, int8_t rT2, uint32_t *temp_ptr)
{
    /* FUNCTION DECLARATIONS */

    /* error return code */
    SaSiError_t Error;

    /* loop variables */
    uint32_t i, j;

    /* aValue - count of right most nulls in P-1 */
    uint32_t aValue, pSizeInWords;

    /* PKA status */
    uint32_t status;
    uint32_t bitVal;

    /* temp buffer 4 words for random generation */
    uint32_t *tempP_ptr, *tempB_ptr;

    /* FUNCTION LOGIC */

    /* ...................... initializations            ............................ */
    /* ------------------------------------------------------------------------------ */

    /* initialize the Error to O.K */
    Error = SaSi_OK;

    /* ------------------------------------------------ */
    /* St. 1. Init variables and registers            */
    /* ------------------------------------------------ */

    /* prime size in words */
    pSizeInWords = CALC_FULL_32BIT_WORDS(PSizeInBits);

    if (sizeof(LLF_pki_key_gen_db_t) != SaSi_PKA_KGDATA_BUFF_SIZE_IN_WORDS * sizeof(uint32_t)) {
        SASI_PAL_LOG_ERR("sizeof(LLF_pki_key_gen_db_t) %d != SaSi_PKA_KGDATA_BUFF_SIZE_IN_WORDS*sizeof(uint32_t) %d",
                         (uint32_t)(sizeof(LLF_pki_key_gen_db_t)),
                         (uint32_t)(SaSi_PKA_KGDATA_BUFF_SIZE_IN_WORDS * sizeof(uint32_t)));
        return 1;
    }

    // first pSizeInWords of temp_ptr is used as temprary buffer by SaSi_RndGenerateWordsArrayInRange
    tempP_ptr = &temp_ptr[pSizeInWords];
    tempB_ptr = &temp_ptr[2 * pSizeInWords];

    /* ................ clearing the temp registers ..................... */
    PKA_2CLEAR(LEN_ID_MAX_BITS, rT0 /* regNum */);
    PKA_2CLEAR(LEN_ID_MAX_BITS, rT1 /* regNum */);
    PKA_2CLEAR(LEN_ID_MAX_BITS, rT2 /* regNum */);

    /* -------------------------------------------------------- */
    /* St. 1.2. Calculate a and m such, that P = 1 + 2^a * m  */
    /*        m=>rT0, a=>aValue                               */
    /* -------------------------------------------------------- */

    /* copy P into register rT0 */
    PKA_COPY(LEN_ID_MAX_BITS, rT0 /* dst */, PKA_REG_N /* src=P */);

    /* rT0 = P - 1 */
    PKA_SUB_IM(LenID + 1, rT0 /* Res */, rT0 /* P */, 1 /* imm */);

    /* set P-1 in tempP buff */
    PKA_CopyDataFromPkaReg(tempP_ptr, pSizeInWords, rT0 /* srcReg */);

    /* a = 1 */
    aValue = 1;

    while (1) {
        /* divide: rT0 = rT0 / 2 */
        PKA_SHR_FILL0(LenID + 1, rT0 /* Res */, rT0 /* P */, 1 - 1 /* OpB */);

        /* test parity of rT0 */
        PKA_READ_BIT0(LenID + 1, rT0 /* P */, bitVal);
        if (bitVal == 0) {
            aValue++;
        } else {
            break;
        }
    }

    /* --------------------------------------------------------------------- */
    /* St. 2. Rabin-Miller test main loop                                    */
    /* --------------------------------------------------------------------- */
    *SuccessCode_ptr = SASI_TRUE;

    for (i = 0; i < testsCount; ++i) {
        /* --------------------------------------------------------------------- */
        /* St. 2.1. Prepare a randon number b, used for the Rabin-Miller test  */
        /*          as the Base of exponentiation. The number must be not      */
        /*          larger, than                           */
        /* --------------------------------------------------------------------- */

        /* generate a random number b=>rT1 for testing the primality of P by  *
         *  exponentiation                                 */
        SaSi_PalMemSetZero(tempB_ptr, sizeof(uint32_t) * pSizeInWords);
        Error = SaSi_RndGenerateWordsArrayInRange(rndContext_ptr, PSizeInBits, tempP_ptr /* (P-1) - maxVect */,
                                                  tempB_ptr /* Rnd */, temp_ptr /* temp buff */);
        if (Error != SaSi_OK) {
            return Error;
        }

        PKA_CopyDataIntoPkaReg(rT1 /* dstReg */, LEN_ID_MAX_BITS, tempB_ptr /* src_ptr */, pSizeInWords);

        /* ------------------------------------------------ */
        /* St. 2.2. Calculate: z = rT1 = z^m mod P        */
        /*        Set j = 0.                              */
        /* ------------------------------------------------ */

        PKA_MOD_EXP(LenID, rT1 /* Res=z */, rT1 /* opA=b */, rT0 /* OpB=m */);
        /* ------------------------------------------------ */
        /* St. 2.3. Check; if z = 1 or z = P-1, then      */
        /*          generate next B                       */
        /* ------------------------------------------------ */
        /* z == 1 ? */
        PKA_COMPARE_IM_STATUS(LenID + 1, rT1 /* z */, 1 /* OpB */, status);
        if (status == 1) {
            goto passed_this_iteration;
        }

        /* rT2 = P - 1 */
        PKA_SUB_IM(LenID + 1, rT2 /* Res */, PKA_REG_N /* P */, 1 /* OpB */);

        /* z == P-1 ? */
        PKA_COMPARE_STATUS(LenID + 1, rT2 /* P */, rT1 /* OpB */, status);
        if (status == 1) {
            goto passed_this_iteration;
        }

        /* ------------------------------------------------ */
        /* St. 2.4. Loop: do while not meet conditions    */
        /*        (j == 0 && z == 1) or (z== P-1 )        */
        /* ---------------------------- ------------------- */
        for (j = 1; j < aValue; j++) {
            /* St. 2.4.1. z= z^2 mod m  */
            PKA_MOD_MUL(LenID, rT1 /* Res */, rT1 /* P */, rT1 /* OpB */);

            /* St. 2.4.2. if z == P-1, then break and next i */
            PKA_COMPARE_STATUS(LenID + 1, rT2 /* P */, rT1 /* OpB */, status);
            if (status == 1) {
                goto passed_this_iteration;
            }

            /* St. 2.4.3. if z == 1, then output composite and stop */
            PKA_COMPARE_IM_STATUS(LenID + 1, rT1 /* P */, 1 /* OpB */, status);
            if (status == 1) {
                *SuccessCode_ptr = SASI_FALSE;
                goto End;
            }

        } /* end for */

        *SuccessCode_ptr = SASI_FALSE;
        goto End;

    passed_this_iteration:;

    } /* end main for */

End:

    /* delete secure sensitive data and exit */
    aValue = 0;
    /* clear temp and tempP */
    SaSi_PalMemSetZero(temp_ptr, 3 * sizeof(uint32_t) * pSizeInWords);

    return Error;

} /* END OF LLF_PKI_KG_X931_MillerRabinTestPKA */

/* ******************************************************************************************** */
/*
 * @brief This function executes the Lucas test according to the the X931 standard.
 *
 * @param[in]  LenID - The ID of entry in RegsSizesTable, containing exact size of P in bits.
 * @param[out] SuccessCode_ptr - the success code : 0 - the test failed , 1 the test passed.
 * @param[in]  CountTests - count of exponentiations in test. If CountTests = 0, then
 *                          CountTests will be set automatically according to prime size, else the
 *                          function performs recieved count of tests.
 * @param[in]  regTemps_ptr - pointer to temp registers list - 7 registers.
 * @param[in]  tempsCount   count of temp registers in the list.
 *
 * assumptions : the max size supported is 2112 bits.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */

static SaSiError_t llfRsaKgX931LucasPrimeTest(uint32_t LenID,             /* In */
                                              int8_t *SuccessCode_ptr,    /* out */
                                              const int8_t *regTemps_ptr, /* In */
                                              uint32_t tempsCount)
{
    /* FUNCTION DECLARATIONS */

    /* the Error identifier */
    SaSiError_t Error;

    /* virtual pointers to registers */
    int8_t rP, rD, rK, rU, rV, rUnew, rVnew, rT;

    /* vector sizes */
    uint32_t kSizeInBits;

    /* internal variables */
    uint32_t d_abs;
    int8_t d_is_positive;

    /* Jacobi result */
    int32_t JacobiRes;

    /* loop variable */
    int32_t i;

    /* PKA status */
    uint32_t status;

    /* FUNCTION LOGIC */

    /* check temp registers count */
#ifdef LLF_PKI_PKA_DEBUG
    if (tempsCount < 7)
        return PKA_NOT_ENOUGH_TEMP_REGS_ERROR;
#else
    tempsCount = tempsCount;
#endif

    /* ........................... initialize local variables ....................... */
    /* ------------------------------------------------------------------------------ */

    /* allocate registers */
    rP    = PKA_REG_N; /* already is initialized by P */
    rD    = regTemps_ptr[0];
    rK    = regTemps_ptr[1];
    rU    = regTemps_ptr[2];
    rV    = regTemps_ptr[3];
    rUnew = regTemps_ptr[4];
    rVnew = regTemps_ptr[5];
    rT    = regTemps_ptr[6];

    /* ............................ setting the d vector .............................. */
    /* -------------------------------------------------------------------------------- */
    /*  clear the temp buffer  */
    PKA_2CLEAR(LEN_ID_MAX_BITS, rD /* regNum */);

    for (d_abs = 5, d_is_positive = 1;; d_abs += 2, d_is_positive = !d_is_positive) {
        /* set D = d_abs  */
        PKA_WRITE_WORD_TO_REG(d_abs, 0, rD);

        /* if D is negative set D = P - D */
        if (d_is_positive == 0) {
            PKA_SUB(LenID + 1, rD /* Res */, rP /* P */, rD /* OpB */);
        }

        Error = llfRsaKgX931Jacobi(LenID, rD, rP, &JacobiRes, rU /* temp */, rV /* temp */, rT /* temp */);

        if (Error != SaSi_OK) {
            return Error;
        }

        if (JacobiRes == -1) {
            break;
        }

    } /* end of loop for finding d */

    /* ............................ init vectors for the test loop ................. */
    /* ----------------------------------------------------------------------------- */

    /* K = P + 1 */
    PKA_ADD_IM(LenID + 1, rK /* Res */, rP /* P */, 1 /* OpB */);

    /* set the size of K in bits */
    kSizeInBits = PKA_GetRegEffectiveSizeInBits(rK /* reg */);

    /* init U and V to 1 */
    PKA_2CLEAR(LEN_ID_MAX_BITS, rU /* regNum */);
    PKA_SET_BIT0(LenID + 1, rU /* Res */, rU /* regNum */);
    PKA_COPY(LEN_ID_MAX_BITS, rV /* dest */, rU /* src */);

    /* ..................... the main test loop      ............................ */
    /* -------------------------------------------------------------------------- */

    for (i = (int32_t)(kSizeInBits - 2); i >= 0; --i) {
        /* a bit value */
        uint32_t bit;

        /* Unew = U*V mod P */
        PKA_MOD_MUL(LenID, rUnew /* Res */, rU /* OpA */, rV /* OpB */);

        /* Vnew = V^2 mod P */
        PKA_MOD_MUL(LenID, rVnew /* Res */, rV /* OpA */, rV /* OpB */);

        /* rT = U^2 */
        PKA_MOD_MUL(LenID, rT /* Res */, rU /* OpA */, rU /* OpB */);

        /* rT= D * U^2 */
        PKA_MOD_MUL(LenID, rT /* Res */, rD /* OpA */, rT /* OpB */);

        /* Vnew = (V^2 + D*U^2) */
        PKA_ADD(LenID + 1, rVnew /* Res */, rT /* OpA */, rVnew /* OpB */);
        /* modular division by 2 */
        PKA_ModDivideBy2(LenID, rVnew, rP /* mod */, rVnew, 0 /* Tag */);

        /* swap V,Vnew and U,Unew */
        PKA_SwapInt8(rVnew, rV);
        PKA_SwapInt8(rUnew, rU);

        /* get bit i from register K */
        bit = PKA_GetBitFromPkaReg(rK, LenID, i, rT);

        if (bit != 0) {
            /* Unew = (U+V)/2 */
            PKA_ADD(LenID + 1, rUnew /* Res */, rV /* OpA */, rU /* OpB */);
            /* modular division by 2 */
            PKA_ModDivideBy2(LenID, rUnew, rP /* mod */, rUnew, 0 /* Tag */);

            /* Vnew = (U*D+V)/2 */
            PKA_MOD_MUL(LenID, rVnew /* Res */, rD /* OpA */, rU /* OpB */);
            PKA_ADD(LenID + 1, rVnew /* Res */, rV /* OpA */, rVnew /* OpB */);
            PKA_ModDivideBy2(LenID, rVnew, rP /* mod */, rVnew, 0 /* Tag */);

            /* swap V,Vnew and U,Unew */
            PKA_SwapInt8(rVnew, rV);
            PKA_SwapInt8(rUnew, rU);

        } /* end of bit is set to 1 */

    } /* end of loop */

    /* U = U mod P */
    PKA_DIV(LenID + 1, rT /* ResNotUsed */, rU /* OpA */, rP /* OpB */);

    /* if U is equal to 0 return success code = 1, else 0 */
    /* ---------------------------------------------------- */

    PKA_COMPARE_IM_STATUS(LenID + 1, rU /* OpA */, 0 /* OpB immed */, status);
    if (status == 1) {
        *SuccessCode_ptr = 1;
    } else {
        *SuccessCode_ptr = 0;
    }

    return Error;

} /* END OF llfRsaKgX931LucasPrimeTest */

/* ********************************************************************************** */
/*
 * @brief This function finds a small auxiliary prime (104...176 bits)
 *        for the Key Generation under the X931 standard.
 *
 * @param [in] LenID  - RegsSizesTable entry, used for setting exact prime size in this function.
 * @param [in,out] rP - The virtual pointer to the prime buff ( assumption its size is 101 bits ).
 * @param [in] rsaKgPrimeTestParams - the pointer to primality testing parameters structure.
 * @param [in] regTemps_ptr - pointer to temp PKA registers list (5 single registers).
 * @param [in] tempsCount - count of temp registers in the list.
 * @param [in] temp_ptr  temp buffer of size 2 max RSA buffer size.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */

static SaSiError_t llfRsaKgX931FindPrime1(SaSi_RND_Context_t *rndContext_ptr, int8_t rP,
                                          LlfRsaKgParams_t *rsaKgPrimeTestParams, const int8_t *regTemps_ptr,
                                          uint32_t tempsCount /* 5 */, uint32_t *temp_ptr)
{
    /* FUNCTION DECLARATIONS */

    /* The error identifier */
    SaSiError_t Error = SaSi_OK;

    /* the reminder and prime product virtual pointers */
    int8_t rPrimeProduct;

    /* temp register */
    int8_t rT, rT1, rT2;

    /* loop variables */
    uint32_t i, c, d;

    /* the rabin miller success code */
    int8_t SuccessCode;

    /* internal variables */
    uint32_t *pTempRem = NULL;
    uint32_t r;

    /* FUNCTION LOGIC */

    /* check temp registers count */
#ifdef LLF_PKI_PKA_DEBUG
    if (tempsCount < 4)
        return PKA_NOT_ENOUGH_TEMP_REGS_ERROR;
#else
    tempsCount = tempsCount;
#endif

    /* ...................... initialize local variables ............................ */
    /* ------------------------------------------------------------------------------ */

    /* allocation of the temp registers */
    rPrimeProduct = regTemps_ptr[0];
    rT            = regTemps_ptr[1];
    rT1           = regTemps_ptr[2];
    rT2           = regTemps_ptr[3];

    /*  clearing the extended temp registers  */
    PKA_2CLEAR(LEN_ID_MAX_BITS, rPrimeProduct /* regNum */);
    PKA_2CLEAR(LEN_ID_MAX_BITS, rT /* regNum */);

    /* set the LSB of the prime to insure it is an odd number: rP_ptr[0] |= 1 */
    PKA_SET_BIT0(LEN_ID_PQ_PKA_REG_BITS /* LenID */, rP /* Res */, rP /* OpA */);

    /* ..................... calculating the prime reminder ................ */
    /* --------------------------------------------------------------------- */
    pTempRem = &temp_ptr[0];

    for (i = 0; i < CALC_PRIME_PRODUCT; ++i) {
        /* load the current prime product into PKA register */
        PKA_WRITE_WORD_TO_REG(g_PrimeProduct[i], 0, rPrimeProduct);

        /* copy rP=>rT and calculate the reminder */
        PKA_COPY(LEN_ID_MAX_BITS, rT /* dest */, rP /* src */);
        PKA_DIV(LEN_ID_PQ_PKA_REG_BITS, rT1 /* resNotUsed */, rT /* OpA */, rPrimeProduct /* OpB */);

        /* read result rT word[0] and load it into reminder word[i] */
        /* ---------------------------------------------------------- */

        PKA_READ_WORD_FROM_REG(pTempRem[i], 0, rT);

    } /* end of loop for calculating the reminders */

    /* .................... the main loop for finding a prime ............. */
    /* -------------------------------------------------------------------- */

    for (d = 0;; d += 2) {
        PKA_2CLEAR(LEN_ID_MAX_BITS, rT /* regNum */);

        /* ................. finding a candidate for a prime ................ */

        for (c = 0, i = 0; i < CALC_PRIME_PRODUCT; ++i) {
            if (pTempRem[i] + d < d) { /* remark: [*] */
                pTempRem[i] -= g_PrimeProduct[i];
            }

            r = pTempRem[i] + d;

            for (; c < g_LastProductPrime[i]; ++c) {
                if (r % g_SmallPrime[c] == 0)
                    goto Next_d;
            }
        }

        /* calculate P = P + d.  */
        /* load d into register rT. Note: rT already cleared, except the LS word  */
        PKA_WRITE_WORD_TO_REG(d, 0, rT);
        PKA_ADD(LEN_ID_PQ_PKA_REG_BITS, rP /* Res */, rP /* OpA */, rT /* OpB */);

        /*  initialization of modular operations  */
        /* ---------------------------------------- */

        /* copy P into modulus register r0 */
        if (rP != PKA_REG_N) {
            PKA_COPY(LEN_ID_MAX_BITS, PKA_REG_N /* dst */, rP /* src */);
        }

        /* initialization of modular operations, the "modulus" in this case is P or Q which is 1/2 modulus size.*
         *  that's the reason we use PQ Len ID                                   */
        PKA_CalcNpIntoPkaReg(LEN_ID_AUX_PRIME_BITS, rsaKgPrimeTestParams->auxPrimesSizeInBits, PKA_REG_N, PKA_REG_NP,
                             rT, rT1);

        /*  executing the Miller-Rabin test   */
        /* ------------------------------------ */
        Error = llfRsaKgX931MillerRabinTest(rndContext_ptr, LEN_ID_AUX_PRIME_BITS,
                                            rsaKgPrimeTestParams->auxPrimesSizeInBits, &SuccessCode, /* out */
                                            rsaKgPrimeTestParams->auxPrimesMilRabTestsCount,         /* in */
                                            rT, rT1, rT2,                                            /* temp registers */
                                            temp_ptr + CALC_PRIME_PRODUCT);
        if (Error != SaSi_OK) {
            return Error;
        }

        /* on sucess return SaSi_OK we have found a prime */
        if (SuccessCode == SASI_TRUE) {
            return SaSi_OK;
        }

        /* update d and reminder to avoid overflow of d (unlikely event) */
        /* --------------------------------------------------------------- */

        for (i = 0; i < CALC_PRIME_PRODUCT; ++i) {
            pTempRem[i] += d; /* remark: since [*] passed, there is no need to recheck */
        }

        d = 0;

    Next_d:
        continue;

    } /* end of main loop for finding a prime */

} /* END OF llfRsaKgX931FindPrime1 */

/* ********************************************************************************** */
/*
 * @brief This function is used to find a valid prime2 (second stage prime) for the
 *        Key Gen under the X9.31 standard .
 *
 * @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param [in,out] rP - The virtual pointer to the prime P (P or Q in RSA).
 * @param [in] rDelta - Te virtual pointer to the delta factor.
 * @param [in] rE - a virtual pointer to public exponent.
 * @param [in] PSizeInBits - size of prime to be generated.
 * @param [in] ESizeInBits - size of exponent.
 * @param [in] testCount   - count of Rabin-miller tests to perform.
 * @param [in] rsaKgPrimeTestParams - the pointer to primality testing parameters structure.
 * @param [in] regTemps_ptr - pointer to temp PKA registers list.
 * @param [in] tempsCount - count of temp registers in the list (6 single registers).
 * @param [in] temp_ptr  temp buffer of size 2 max RSA buffer size.
 *
 * assumptions : This function supports a fixed size of 101 bits as required in the standard.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */

static SaSiError_t llfRsaKgX931FindPrime2(SaSi_RND_Context_t *rndContext_ptr,
                                          int8_t rP, // its actual size is 1/2 modulus;
                                          int8_t rDelta, int8_t rE, uint32_t PSizeInBits,
                                          LlfRsaKgParams_t *rsaKgPrimeTestParams, const int8_t *regTemps_ptr,
                                          uint32_t tempsCount, uint32_t *temp_ptr)
{
    /* FUNCTION DECLARATIONS */

    /* error identifier */
    SaSiError_t Error;

    /* the reminder and prime product virtual pointers */
    int8_t rPrimeProduct;

    /* temp register */
    int8_t rT, rT1, rT2;

    /* Lucas and Rabin-Miller tests result */
    int8_t SuccessCode;

    /* loop variables */
    uint32_t i, c;

    /* PKA status */
    uint32_t status;
    uint32_t bitVal;

    uint32_t *pTempRem   = NULL;
    uint32_t *pTempDelta = NULL;

    /* FUNCTION LOGIC */

    /* check temp registers count */
#ifdef LLF_PKI_PKA_DEBUG
    if (tempsCount < 4)
        return PKA_NOT_ENOUGH_TEMP_REGS_ERROR;
#endif

    /* ............................ initialize local variables ............................ */
    /* ------------------------------------------------------------------------------------ */
    /* init the error to success */
    Error = SaSi_OK;

    /* allocation of the reminder and product on temp registers */
    rPrimeProduct = regTemps_ptr[0];
    rT            = regTemps_ptr[1];
    rT1           = regTemps_ptr[2];
    rT2           = regTemps_ptr[3];

    /* ..................... calculating the prime reminder ................ */
    /* --------------------------------------------------------------------- */

    /*  clearing the temp registers (extended) */
    PKA_2CLEAR(LEN_ID_MAX_BITS, rPrimeProduct /* regNum */);
    PKA_2CLEAR(LEN_ID_MAX_BITS, rT /* regNum */);

    /* ................... calculate Rdelta and the Reminder ................ */
    /* ---------------------------------------------------------------------- */

    /* if the prime candidate P is even add the delta */
    PKA_READ_BIT0(LEN_ID_PQ_PKA_REG_BITS, rP /* OpA */, bitVal);
    if (bitVal == 0) {
        PKA_ADD(LEN_ID_PQ_PKA_REG_BITS /* LenID */, rP /* Res */, rP /* OpA */, rDelta /* OpB */);
    }

    /* multiply delta by 2 */
    PKA_ADD(LEN_ID_PQ_PKA_REG_BITS /* LenID */, rDelta /* Res */, rDelta /* OpA */, rDelta /* OpB */);

    /* ........loop for calculating the products ....... */
    /* -------------------------------------------------- */
    pTempRem   = &temp_ptr[0];
    pTempDelta = &temp_ptr[CALC_PRIME_PRODUCT];

    for (i = 0; i < CALC_PRIME_PRODUCT; ++i) {
        /* load the current rPrimeProduct[0] = g_PrimeProduct[i] */
        PKA_WRITE_WORD_TO_REG(g_PrimeProduct[i], 0, rPrimeProduct);

        /* copy rP=>rT and calculate the reminder in reg rT */
        PKA_COPY(LEN_ID_MAX_BITS, rT /* dest */, rP /* src */);
        PKA_DIV(LEN_ID_PQ_PKA_REG_BITS, rT1 /* ResNotUsed */, rT /* OpA */, rPrimeProduct /* OpB */);

        /* load the next word of reminder: rRem[i] = rT[0] */
        PKA_READ_WORD_FROM_REG(pTempRem[i], 0, rT);

        /* calculate the Rdelta */
        PKA_COPY(LEN_ID_MAX_BITS, rT /* dest */, rDelta /* src */);
        PKA_DIV(LEN_ID_PQ_PKA_REG_BITS, rT1 /* ResNotUsed */, rT /* OpA */, rPrimeProduct /* OpB */);

        /* load the Rdelta with the result rRdeltam[i] = rT[0] */
        PKA_READ_WORD_FROM_REG(pTempDelta[i], 0, rT);

    } /* end of loop for calculating the reminders */

    /* ------------------------------------------------------------------------ */
    /* ..................... main loop for finding the prime .................. */
    /* ------------------------------------------------------------------------ */

    while (1) {
        // WATCH_DOG_RESET(); // obsolete. Watchdog should be fed by dedicated task

        /* checking if the current prime should be tested */
        for (c = 0, i = 0; i < CALC_PRIME_PRODUCT; i++) {
            for (; c < g_LastProductPrime[i]; c++) {
                if ((pTempRem[i] % g_SmallPrime[c]) == 0) {
                    goto NextPrime;
                }
            }
        }

        /* .......... execute rT = GCD(e,P-1) ............. */
        /* -------------------------------------------------- */

        PKA_SUB_IM(LEN_ID_PQ_PKA_REG_BITS, rT /* Res */, rP /* OpA */, 1 /* imm */); /* rP= rP-1 */
        PKA_COPY(LEN_ID_MAX_BITS, PKA_REG_N /* dest */, rE /* src */);

        /* rT = GCD */
        PKA_MOD_INV(LEN_ID_PQ_BITS, rT1 /* Res */, rT /* OpA */);

        /* if the GCD != 1, go to the next prime */
        PKA_COMPARE_IM_STATUS(LEN_ID_PQ_PKA_REG_BITS, rT /* OpA */, 1 /* OpB */, status);
        if (status != 1) {
            goto NextPrime;
        }

        /*  initialization of modular operations for modulus P */
        /* ----------------------------------------------------- */

        /* reset modulus in register r0 = rP */
        PKA_COPY(LEN_ID_MAX_BITS, PKA_REG_N /* dst */, rP /* src */);

        /* initialization of modular operations */
        PKA_CalcNpIntoPkaReg(LEN_ID_PQ_BITS, PSizeInBits, PKA_REG_N, PKA_REG_NP, rT, rT1);

        /* .........  perform primality tests   ............ */
        /* --------------------------------------------------- */

        /* init lhe test flag to FALSE */
        SuccessCode = SASI_FALSE;

        /* execute the Miller-Rabin test */
        Error = llfRsaKgX931MillerRabinTest(rndContext_ptr, LEN_ID_PQ_BITS, PSizeInBits, &SuccessCode, /* out */
                                            rsaKgPrimeTestParams->pqPrimesMilRabTestsCount, /* count R-M Tests */
                                            rT, rT1, rT2,                                   /* temp registers */
                                            temp_ptr + 2 * CALC_PRIME_PRODUCT);
        if (Error != SaSi_OK) {
            goto End; // LR goto ClearAndReturn
        }

        /* if the previous test succeeded, execute the Lucas test */
        if (SuccessCode == SASI_TRUE) {
            Error = llfRsaKgX931LucasPrimeTest(LEN_ID_PQ_BITS, &SuccessCode, /* out */
                                               regTemps_ptr + 3,             /* temp registers list */
                                               tempsCount - 3);
            if (Error != SaSi_OK) {
                goto End; // LR goto ClearAndReturn
            }
        }

        /* if both tests are passed, exit - we have finded a prime */
        if (SuccessCode == SASI_TRUE) {
            return SaSi_OK;
        }

    /* -------------------------------------------- */
    /*    finding the next prime candidate        */
    /* -------------------------------------------- */
    NextPrime:

        /* updating of remainders Rem[i] */
        for (i = 0; i < CALC_PRIME_PRODUCT; i++) {
            pTempRem[i] += pTempDelta[i];
            if (pTempRem[i] < pTempDelta[i]) {
                pTempRem[i] -= g_PrimeProduct[i];
            }
        }

        /* the new prime candidate: P = P + Delta */
        PKA_ADD(LEN_ID_PQ_PKA_REG_BITS, rP /* Res */, rP /* OpA */, rDelta /* OpB */);

    } /* end of searching for a prime loop */

End:
    // RL  Check and ddd Clearing temp buffers if need !!!!
    return Error;

} /* END OF llfRsaKgX931FindPrime2 */

/* ********************************************************************************** */
/*
 * @brief This function is used to find a valid prime for the Key Gen under
 *        the X931 standard .
 *
 *     Assumes: - the PKA is initialized on default mode according to PSizeInBits,
 *              - the PSizeInBits is set into LenID RegsSizesTable,
 *
 * @param [in/out] rndContext_ptr  - pointer to the RND context buffer.
 * @param [in] rP1,rP2 - the virtual pointers to PKA registers of auxiliary primes p1,p2.
 * @param [in/out] rP - the virtual pointer to the register containing P prime.
 * @param [in] PSizeInBits - size of the prime P.
 * @param [in] rE - the virtual pointer to public exponent.
 * @param [in] rsaKgPrimeTestParams - the pointer to primality testing parameters structure.
 * @param [in] regTemps_ptr - the pointer to temp PKA registers list (7 single registers).
 * @param [in] tempsCount - count of temp registers in the list.
 * @param [in] temp_ptr - the pointer to the temp buffer of size 2 max RSA buffer size.
 *
 * assumptions : This function supports a fixed size of 101 bits as required in the standard.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */

static SaSiError_t llfRsaKgX931FindPrime(SaSi_RND_Context_t *rndContext_ptr, int8_t rP1 /* *p1_ptr */,
                                         int8_t rP2 /* *p2_ptr */, int8_t rP /* *prime_ptr */, uint32_t PSizeInBits,
                                         uint32_t rE /* e_ptr */, LlfRsaKgParams_t *rsaKgPrimeTestParams,
                                         const int8_t *regTemps_ptr, uint32_t tempsCount, uint32_t *temp_ptr)
{
    /* FUNCTION LOCAL DECLARATIONS */

    /* the Error identifier */
    SaSiError_t Error = SaSi_OK;

    /* virtual pointers to PKA registers */
    int8_t rP12, rPmodP12, rR1, rR2;

    /* virtual pointers to temp PKA registers */
    int8_t rT1;

    /* PKA status */
    uint32_t status, flag;

    /* FUNCTION LOGIC */

    /* ............... init local variables .............................. */
    /* ------------------------------------------------------------------- */

    /* allocation of registers */
    rP12     = regTemps_ptr[0];
    rPmodP12 = regTemps_ptr[1];
    rR1      = regTemps_ptr[2];
    rR2      = regTemps_ptr[3];
    rT1      = regTemps_ptr[4];

    /* check temp registers count */
#ifdef LLF_PKI_PKA_DEBUG
    if (tempsCount < 5)
        return PKA_NOT_ENOUGH_TEMP_REGS_ERROR;
#endif

    /* ...... find the first primes P1, P2  of size 101 bit .............. */
    /* ------------------------------------------------------------------- */
    /* p1 */
    Error = llfRsaKgX931FindPrime1(rndContext_ptr, rP1, rsaKgPrimeTestParams, regTemps_ptr, tempsCount, temp_ptr);
    if (Error != SaSi_OK)
        return Error;

    /* p2 */
    Error = llfRsaKgX931FindPrime1(rndContext_ptr, rP2, rsaKgPrimeTestParams, regTemps_ptr, tempsCount, temp_ptr);
    if (Error != SaSi_OK) {
        return Error;
    }

    /* Debug */
#ifdef LLF_PKI_PKA_DEBUG
    PKA_COPY(LEN_ID_MAX_BITS, rP1 /* dst */, rP1 /* src */);
    PKA_COPY(LEN_ID_MAX_BITS, rP2 /* dst */, rP2 /* src */);
#endif

    /*  find P12 = P1*P2 , pModP12 = P mod P12 (operations size from LenID) */
    /*     Note: PSizeInBits must be set into LenID entry                   */
    /* -------------------------------------------------------------------- */

    /* P12 = P1 * P2 */
    PKA_MUL_LOW(LEN_ID_PQ_PKA_REG_BITS, rP12 /* Res */, rP1 /* OpA */, rP2 /* OpB */);

    /* PmodP12 = P mod P12 */
    PKA_COPY(LEN_ID_MAX_BITS, rPmodP12 /* dst */, rP /* src */);
    PKA_DIV(LEN_ID_PQ_PKA_REG_BITS, rT1 /* ResNotUsed */, rPmodP12 /* OpA */, rP12 /* OpB */);

    /* find; R1= (1/P2 mod P1)*P2 - (1/P1 mod P2)*P1; R2= ... similary   .. */
    /* -------------------------------------------------------------------- */

    /* ....... calculate R1 = (1/P2 mod P1)*P2 ..... */
    PKA_COPY(LEN_ID_MAX_BITS, PKA_REG_N /* mod reg */, rP1 /* src */);
    PKA_2CLEAR(LEN_ID_MAX_BITS, rT1 /* dst */);
    PKA_COPY(LEN_ID_MAX_BITS, rT1 /* dst */, rP2 /* src */);

    /* if P1 > P2 set flag = 1, else flag = 0 */
    PKA_SUB(LEN_ID_PQ_PKA_REG_BITS, RES_DISCARD, rP2 /* OpA */, rP1 /* OpB */);
    PKA_GET_StatusCarry(status);
    if (status == 0) {
        flag = 1;
    } else {
        /* set rT1 = P2 mod P1 = rT1 - rP1 */
        flag = 0;
        PKA_SUB(LEN_ID_PQ_PKA_REG_BITS, rT1 /* Res */, rT1 /* OpA */, rP1 /* OpB */);
    }

    /* R1 = (1/P2 mod P1) */
    /* we know PKA_REG_N - rP1 is prime, so we can use ModInv with the odd number */
    /* we do not check GCD, since PKA_REG_N is prime and rT1 < PKA_REG_N. therfore GCD must be 1 */
    PKA_MOD_INV(LEN_ID_PQ_BITS, rR1 /* Res */, rT1 /* OpB */);

    PKA_MUL_LOW(LEN_ID_PQ_PKA_REG_BITS, rR1 /* Res */, rR1 /* OpA */, rP2 /* OpB */);

    /* ....... calculate R2 = (1/P1 mod P2)*P1 ..... */
    PKA_COPY(LEN_ID_MAX_BITS, PKA_REG_N /* mod reg */, rP2 /* src */);
    PKA_2CLEAR(LEN_ID_MAX_BITS, rT1 /* dst */);
    PKA_COPY(LEN_ID_MAX_BITS, rT1 /* dst */, rP1 /* src */);

    /* if flag == 1, i.e. P2 >= P1, then set rT1 = P1 mod P2 = P1 - P2 */
    if (flag == 1) {
        PKA_SUB(LEN_ID_PQ_PKA_REG_BITS, rT1 /* Res */, rT1 /* OpA */, rP2 /* OpB */);
    }

    /* we know PKA_REG_N = rP2 is prime, so we can use ModInv with the odd number */
    PKA_MOD_INV(LEN_ID_PQ_BITS, rR2 /* Res */, rT1 /* OpB */);

    PKA_MUL_LOW(LEN_ID_PQ_PKA_REG_BITS, rR2 /* Res */, rR2 /* OpA */, rP1 /* OpB */);

    /* R=R1-R2; if(R <0) R= R+P12; */
    /* R1 and R2 are max 202 bits each, so LEN_ID_PQ_BITS should be enought to hold negative number */
    PKA_SUB(LEN_ID_PQ_PKA_REG_BITS, rR1 /* res */, rR1 /* OpA */, rR2 /* OpB */);
    PKA_GET_StatusCarry(status);
    if (status == 0) {
        PKA_ADD(LEN_ID_PQ_PKA_REG_BITS, rR1 /* res */, rR1 /* OpA */, rP12 /* OpB */);
    }

    /* R=R-PmodP12; if(R<0) R=R+P12; */
    PKA_SUB(LEN_ID_PQ_PKA_REG_BITS, rR1 /* res */, rR1 /* OpA */, rPmodP12 /* OpB */);
    PKA_GET_StatusCarry(status);
    if (status == 0) {
        PKA_ADD(LEN_ID_PQ_PKA_REG_BITS, rR1 /* res */, rR1 /* OpA */, rP12 /* OpB */);
    }

    /* add P = P + R */
    PKA_ADD(LEN_ID_PQ_PKA_REG_BITS, rP /* res */, rP /* OpA */, rR1 /* OpB */);

    /* find the prime P */
    Error = llfRsaKgX931FindPrime2(rndContext_ptr, rP, rP12 /* rDelta */, rE, PSizeInBits, rsaKgPrimeTestParams,
                                   regTemps_ptr + 1, tempsCount - 1, temp_ptr);

    return Error;

} /* END OF llfRsaKgX931FindPrime */

/* ********************************************************************************** */
/*
 * @brief The function checks primality of big number relating to set of small prime numbers.
 *
 *   Notes:  - 3 PKA registers used: rP, rModRes, rSmallNum,
 *           - the PKA must be initialized according tp P size,
 *           - LenID+1 entry containing the extended register size.
 *
 * @param[in] LenID     - The SizesTable entry, containing the exact P size in bits.
 * @param[in] rP        - The virtual pointer to big number P register to be checked.
 * @param[in] rModRes   - The virtual pointer to temp register.
 * @param[in] rSmallNum - The virtual pointer to temp register.
 * @param[in] rT        - The virtual pointer to temp register.
 *
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure an error code.
 *
 */
static int32_t llfRsaKgQuickPrimeTest(uint8_t LenID,      /* in */
                                      int8_t rP,          /* in */
                                      int8_t rModRes,     /* temp reg */
                                      int8_t rSmallPrime, /* temp reg */
                                      int8_t rT,          /* temp reg */
                                      uint32_t divCount)  /* in */
{
    /* FUNCTION DECLARATIONS */

    /* loop variable */
    uint32_t i;
    /* PKA status */
    uint32_t status;

    /* set pointer smallPrime_ptr to PKA register low word */
    /* clear rSmallPrime register (with extension) */
    PKA_2CLEAR(LEN_ID_MAX_BITS, rSmallPrime /* OpA */);

    /* ----------------------------------------------- */
    /* Check primality by dividing P by small primes */
    /* ----------------------------------------------- */

    for (i = 0; i < divCount; i++) {
        /* copy rP into rModReg for dividing */
        PKA_COPY(LEN_ID_MAX_BITS, rModRes /* dst */, rP /* src */);

        /* set the next small prime into PKA register */
        PKA_WRITE_WORD_TO_REG(g_SmallPrime[i], 0, rSmallPrime);

        /* calculate remainder: rModReg = rP % smallPrime */
        PKA_DIV(LenID + 1, rT /* ResNotUsed */, rModRes /* OpA */, rSmallPrime /* OpB */);

        /* check is the remainder equaled to 0 by add operation */
        PKA_ADD_IM(LenID + 1, RES_DISCARD /* discard Res */, rModRes /* OpA */, 0 /* OpB */);
        PKA_GET_StatusAluOutZero(status);
        if (status) {
            return SASI_FALSE;
        }
    }

    /* End - return SUCCESS */

    return SASI_TRUE;

} /* End of llfRsaKgQuickPrimeTest() */

/* ********************************************************************************** */
/*                  Public functions                                                 */
/* ********************************************************************************** */

/* ********************************************************************************** */
/*
 * @brief This function is used to fined a valid prime for the Key Gen.
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param[in,out] rP - The virtual pointer to the prime P register.
 * @param[in] PSizeInBits - The prime size in bits.
 * @param[in] rE - The virtual pointer to the public exponent register.
 * @param[in] ESizeInBits - The public exponent size in bits.
 * @param[in] rsaKgPrimeTestParams - the pointer to primality testing parameters structure.
 * @param[in] regTemps_ptr - pointer to temp PKA registers list (9 single registers
 *            of size according to PSizeInBits ).
 * @param[in] tempsCount - count of temp registers in the list (9).
 * @param[in] temp_ptr  temp buffer of size 2 max RSA buffer size.
 *
 * assumptions : .
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
static SaSiError_t llfRsaKgFindPrime(SaSi_RND_Context_t *rndContext_ptr, int8_t rP, uint32_t PSizeInBits, int8_t rE,
                                     LlfRsaKgParams_t *rsaKgPrimeTestParams, const int8_t *regTemps_ptr,
                                     uint32_t tempsCount, uint32_t *temp_ptr)
{
    /* LOCAL DECLARATIONS */

    /* the Error identifier */
    SaSiError_t Error = SaSi_OK;

    /* virtual pointers to PKA data registers */
    int8_t rP1, rP2;

    /* temp buffer for auxiliary random number / big end
       1E05B8F18D807DB7A47EF53567 nearest random is: 1E 05 B8 F1 8D 80 7D
       B7 A4 7E F5 35 99 */
    uint32_t rBuff[PKA_RSA_AUX_PRIME_BUFF_SIZE_IN_32BIT_WORDS] = { 0 };
    uint32_t auxPrimeSizeInBytes, auxPrimeSizeInWords;
    uint32_t mask, msBit;

    SaSi_RND_State_t *rndState_ptr;
    SaSiRndGenerateVectWorkFunc_t RndGenerateVectFunc;

    /* FUNCTION LOGIC */

    /* check parameters */
    if (rndContext_ptr == NULL) {
        return SaSi_RND_CONTEXT_PTR_INVALID_ERROR;
    }

    rndState_ptr        = &(rndContext_ptr->rndState);
    RndGenerateVectFunc = rndContext_ptr->rndGenerateVectFunc;

    if (RndGenerateVectFunc == NULL) {
        return SaSi_RND_GEN_VECTOR_FUNC_ERROR;
    }

#ifdef LLF_PKI_PKA_DEBUG
    if (tempsCount < 2)
        return PKA_NOT_ENOUGH_TEMP_REGS_ERROR;
#endif

    /* allocate virtual pointers on temp registers */
    rP1 = regTemps_ptr[0];
    rP2 = regTemps_ptr[1];

    /* calculate size of aux. primes in bytes and words */
    auxPrimeSizeInBytes = CALC_FULL_BYTES(rsaKgPrimeTestParams->auxPrimesSizeInBits);
    auxPrimeSizeInWords = CALC_FULL_32BIT_WORDS(rsaKgPrimeTestParams->auxPrimesSizeInBits);

#if defined RSA_KG_NO_RND
#ifdef LLF_PKI_PKA_DEBUG

    if (PQindex == 0) {
        SaSi_PalMemCopy(rBuff, rBuff1, auxPrimeSizeInBytes); /* for P */
    } else {
        SaSi_PalMemCopy(rBuff, rBuff3, auxPrimeSizeInBytes); /* for Q */
    }

#ifdef BIG__ENDIAN
    SaSi_COMMON_INVERSE_UINT32_IN_ARRAY(rBuff, auxPrimeSizeInWords);
#endif
#endif

#else
    /* calculate mask for aux.prime candidate */
    mask  = (~0UL >> (32 - (rsaKgPrimeTestParams->auxPrimesSizeInBits & 0x1F)));
    msBit = 1UL << (rsaKgPrimeTestParams->auxPrimesSizeInBits & 0x1F);

    /* get a random auxiliary number P1      */
    /* --------------------------------------- */
    Error = RndGenerateVectFunc(rndState_ptr, auxPrimeSizeInBytes, (uint8_t *)rBuff);
    if (Error != SaSi_OK) {
        return Error;
    }
#endif

    /* calculate mask and set MS bit of aux.prime candidate */
    rBuff[auxPrimeSizeInWords - 1] &= mask;
    rBuff[auxPrimeSizeInWords - 1] |= msBit;
    /* set LSBit = 1 to ensure the odd number */
    rBuff[0] |= 1UL;

#ifdef LLF_PKI_PKA_DEBUG
#if (defined RSA_KG_NO_RND || defined RSA_KG_FIND_BAD_RND)
    /* set pointers for extern P,Q and aux.primes buffers */
    if (PQindex == 0) {
        P1R_ptr  = P1pR;
        P2R_ptr  = P2pR;
        P1Pr_ptr = P1pPr;
        P2Pr_ptr = P2pPr;
        PQ_ptr   = rBuffP;
    } else {
        P1R_ptr   = P1qR;
        P2R_p tr  = P2qR;
        P1Pr_ptr  = P1qPr;
        P2P r_ptr = P2qPr;
        PQ_ptr    = rBuffQ;
    }

    SaSi_PalMemCopy(P1R_ptr, rBuff, auxPrimeSizeInBytes); /* for P */

#endif
#endif

    /* copy random number into PKA register rP1 */
    PKA_CopyDataIntoPkaReg(rP1 /* dstReg */, LEN_ID_MAX_BITS, rBuff /* src_ptr */, auxPrimeSizeInWords);

    /* ------------------------------------------------------- */
#ifdef RSA_KG_NO_RND
#ifdef LLF_PKI_PKA_DEBUG
    rBuff[3] = 0;
    if (PQindex == 0) {
        SaSi_PalMemCopy(rBuff, rBuff2, auxPrimeSizeInBytes); /* for P */
    } else {
        SaSi_PalMemCopy(rBuff, rBuff4, auxPrimeSizeInBytes); /* for Q */
    }

#ifdef BIG__ENDIAN
    SaSi_COMMON_INVERSE_UINT32_IN_ARRAY(rBuff, auxPrimeSizeInWords);
#endif
#endif

#else

    /* get a random auxiliary number P2     */
    /* --------------------------------------- */
    SaSi_PalMemSetZero(rBuff, sizeof(rBuff));
    Error = RndGenerateVectFunc(rndState_ptr, auxPrimeSizeInBytes, (uint8_t *)rBuff);
    if (Error != SaSi_OK) {
        return Error;
    }

#endif

    /* set MS bit of P2 */
    rBuff[auxPrimeSizeInWords - 1] &= mask;
    rBuff[auxPrimeSizeInWords - 1] |= msBit;
    /* set LSBit = 1 to ensure the odd number */
    rBuff[0] |= 1UL;

    /*  Debug  */
#ifdef LLF_PKI_PKA_DEBUG
#if defined RSA_KG_FIND_BAD_RND
    SaSi_PalMemCopy(P2R_ptr, rBuff, auxPrimeSizeInBytes); /* for P */
#endif
#endif

    /* copy random number P2 into PKA register rP2 */
    PKA_CopyDataIntoPkaReg(rP2 /* dstReg */, LEN_ID_MAX_BITS, rBuff /* src_ptr */, auxPrimeSizeInWords);

    /*           find the primes P1,P2, P              */
    /* ------------------------------------------------- */
    Error = llfRsaKgX931FindPrime(rndContext_ptr, rP1, rP2, /* aux.primes */
                                  rP,                       /* prime */
                                  PSizeInBits, rE,          /* exp */
                                  rsaKgPrimeTestParams, regTemps_ptr + 2, tempsCount - 2, temp_ptr);

    /* Debug */
#ifdef LLF_PKI_PKA_DEBUG
#if (defined RSA_KG_NO_RND || defined RSA_KG_FIND_BAD_RND)
    /* save found results: rP1,rP2,rP for P and Q accordingly */
    PKA_CopyDataFromPkaReg(P1Pr_ptr /* dst_ptr */, auxPrimeSizeInWords, rP1 /* srcReg */);

    PKA_CopyDataFromPkaReg(P2Pr_ptr /* dst_ptr */, auxPrimeSizeInWords, rP2 /* srcReg */);

    PKA_CopyDataFromPkaReg(PQ_ptr /* dst_ptr */, PSizeInBits / 8, rP /* srcReg */);
#endif
#endif

    return Error;

} /* END OF llfRsaKgFindPrime */

/* ********************************************************************************** */
/*
 * @brief This function is used to test a primality of big numbers.
 *
 *        The function performs assigned count of Rabin-Miller tests and one Lucas-Lehmer
 *        test according to testing mode:
 *              - for RSA according to ANSI X9.31 standard.
 *              - for DH  according to ANSI X9.42 standard.
 *
 * @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param [in] P_ptr           - The pointer to the prime buff.
 * @param [in] sizeWords       - The prime size in words.
 * @param [in] rabinTestsCount - The count of Rabin-Miller tests repetition.
 * @param [in] isPrime         - The flag indicates primality:
 *                               if is not prime - SASI_FALSE, otherwise - SASI_TRUE.
 * @param [in] primeTestMode - primality testing mode (RSA or DH - defines how are performed some
 *             operations on temp buffers.
 * @param [in] temp_ptr - temp buffer of size 2*sizeWords.
 *
 *         NOTE:  For using in RSA module  size of each temp buffer must be of minimum size
 *                of prime number P in words.
 *                For using in ANSI X9.42 standard (DH,DSA algorithms) size of each temp buffer
 *                must be minimum of two size of prime number P in words.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure an error code.
 *
 */

static SaSiError_t llfRsaKgPrimeTest(SaSi_RND_Context_t *rndContext_ptr, uint32_t *P_ptr, int32_t sizeWords,
                                     int32_t rabinTestsCount, int8_t *isPrime_ptr,
                                     SaSi_RSA_DH_PrimeTestMode_t primeTestMode, uint32_t *temp_ptr)
{
    /* FUNCTION DECLARATIONS */

    /* the Error identifier */
    SaSiError_t Error = SaSi_OK;

    /* virtual pointers to PKA regs */
    /* set registers pointers, note: r0=PKA_REG_N, r1=PKA_REG_NP by default reserved for N and NP */
    uint8_t rT2 = regTemps[2];
    uint8_t rT3 = regTemps[3];
    uint8_t rT4 = regTemps[4]; /* temp registers */

    uint32_t PSizeInBits;
    uint32_t divCount;
    uint32_t pkaReqRegs = 11;

    /* FUNCTION  LOGIC */

    /*         Initializations          */
    /* ---------------------------------- */

    /* exact size of P */
    PSizeInBits = SASI_BITS_IN_32BIT_WORD * sizeWords;

    /* ------------------------------------------------------------------------ */
    /* initialize the PKA engine on default mode with size of registers       */
    /* according to operation size = max(Asize,Bsize)                         */
    /* ------------------------------------------------------------------------ */

    Error = PKA_CalcNp(temp_ptr, P_ptr, PSizeInBits);
    if (Error != SaSi_OK) {
        return Error;
    }

    Error = PKA_InitAndMutexLock(PSizeInBits, &pkaReqRegs);
    if (Error != SaSi_OK) {
        return Error;
    }

    /* set modulus into PKA register r0 */
    PKA_CopyDataIntoPkaReg(PKA_REG_N /* dstReg */, LEN_ID_MAX_BITS /* LenID */, P_ptr /* src_ptr */, sizeWords);

    /* copy Np to PKA register #1 */
    PKA_CopyDataIntoPkaReg(PKA_REG_NP /* dstReg */, LEN_ID_MAX_BITS /* LenID */, temp_ptr /* src_ptr */,
                           SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);

    /* --------------------------------- */
    /*   execute primality tests       */
    /* --------------------------------- */

    /* count of small primes (each one is DxUint16) to check:
        - for DH algorithm use predefined value,
          else use maximal value  */

    if (primeTestMode == SaSi_DH_PRIME_TEST_MODE) {
        divCount = LLF_PKI_QUICK_PRIME_TEST_DIVISIONS_COUNT;
    } else {
        divCount = sizeof(g_SmallPrime) / sizeof(uint16_t);
    }

    /* test by small prime numbers */
    *isPrime_ptr = (int8_t)llfRsaKgQuickPrimeTest(LEN_ID_N_BITS /* LenID */, PKA_REG_N /* prime P */, rT2, rT3,
                                                  rT4 /* temp regs */, divCount);

    /* the Miller-Rabin test */
    if (*isPrime_ptr == SASI_TRUE) {
        Error = llfRsaKgX931MillerRabinTest(rndContext_ptr, LEN_ID_N_BITS /* LenID */, PSizeInBits, isPrime_ptr, /* out */
                                            rabinTestsCount, rT2, rT3, rT4 /* temp regs */, temp_ptr);
        if (Error != SaSi_OK) {
            goto End;
        }
    }

    /* the Lucas test  */
    if (*isPrime_ptr == SASI_TRUE) {
        Error = llfRsaKgX931LucasPrimeTest(LEN_ID_N_BITS /* LenID */, isPrime_ptr, /* out */
                                           regTemps + 2, 7 /* tempsCount */);
    }
End:
    PKA_FinishAndMutexUnlock(pkaReqRegs);

    return Error;

} /* END OF llfRsaKgPrimeTest */

/* ********************************************************************************** */
/*
 * @brief The LLF_PKI_CalculateNandD calculates RSA modulus and private key in NonCRT mode.
 *
 *    The function initializes the PKA according to used registers size, calculates
 *    keys components and finishes PKA operations.
 *
 *    Note: the PKA is locked by caller function.
 *
 * @param[in]  e_ptr             - The pointer to the public exponent.
 * @param[in]  eSizeInBits       - The public exponent size in bits.
 * @param[in]  p_ptr             - The first factor pointer (LSWord is the left most).
 * @param[in]  q_ptr             - The second factor pointer (LSWord is the left most).
 * @param[in]  primeSizeInBits   - The sze of the prime factors in bits.
 * @param[out] n_ptr             - The pointer to the RSA modulus buffer.
 * @param[out] d_ptr             - The pointer to the private exponent (non CRT).
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */

static SaSiError_t PKA_CalculateNandD(uint32_t *e_ptr, uint32_t eSizeInBits, uint32_t *p_ptr, uint32_t *q_ptr,
                                      uint32_t primeSizeInBits, uint32_t *n_ptr, uint32_t *d_ptr)
{
    /* LOCAL DECLARATIONS */

    SaSiError_t Error = SaSi_OK;

    /* define virtual pointers to PKA registers */
    uint32_t r0   = PKA_REG_N; /* mod */
    uint32_t rLcm = 1;
    uint32_t rP   = 2;
    uint32_t rQ   = 3;
    uint32_t rD   = 4;
    uint32_t rT   = 5;

    /* modulus size in bits and bytes */
    uint32_t primeSizeInWords, i;
    /* count of needed PKA registers */
    uint32_t pkaRegsCount = 7;

    /* FUNCTION LOGIC */

    /* ...................... initialize local variables ............................ */

    /* setting the primes P,Q length in bytes */
    primeSizeInWords = CALC_FULL_32BIT_WORDS(primeSizeInBits);

    /* init PKA without mutex lock/unlock */
    Error = PKA_InitPka(2 * primeSizeInBits, GET_FULL_OP_SIZE_PKA_WORDS(2 * primeSizeInBits), &pkaRegsCount);
    if (Error != SaSi_OK) {
        return Error;
    }
    PKA_SetLenIds(primeSizeInBits, LEN_ID_PQ_BITS);
    PKA_SetLenIds(GET_FULL_OP_SIZE_BITS(primeSizeInBits), LEN_ID_PQ_PKA_REG_BITS);

    /* clear pka memory for new using */
    PKA_ClearBlockOfRegs(0 /* firstReg */, pkaRegsCount, LEN_ID_MAX_BITS);

    /*  copy P, Q into PKA registers. Note: now size of registers is full.  */
    PKA_CopyDataIntoPkaReg(rP /* dstReg */, LEN_ID_MAX_BITS, p_ptr /* src_ptr */, primeSizeInWords);

    PKA_CopyDataIntoPkaReg(rQ /* dstReg */, LEN_ID_MAX_BITS, q_ptr /* src_ptr */, primeSizeInWords);

    /* **************************************************************************************** */
    /*                     CALCULATIONS WITH LONG REGISTERS                                    */
    /*  Init the PKA again on default mode according to N operation size.                      */
    /*  Note: All PKA memory shall be cleaned, nSizeInBits=> entry 0, nSizeInBits+SASI_PKA_WORD_SIZE_IN_BITS=> entry 1
     */
    /* **************************************************************************************** */
    if (n_ptr != NULL) {
        /* ----------------------------------------------- */
        /*     N= r0= P*Q. LenID = 0 for full reg size   */
        /* ----------------------------------------------- */

        PKA_MUL_LOW(LEN_ID_N_BITS, r0, rP /* OpA */,
                    rQ /* OpB */); // use LEN_ID_N_BITS, since its size is 2*primeSizeInBits

        /* output the modulus N for releasing the r0 register, used also for LCM */
        PKA_CopyDataFromPkaReg(n_ptr, 2 * primeSizeInWords, r0 /* srcReg */);
    }

    if (d_ptr != NULL) {
        bool isTrue = false;
        uint32_t stat;

        /* -------------------------------------------------------------------------------- */
        /* .............     calculate D = E^-1 mod LCM(P-1)*(Q-1)           ............. */
        /* -------------------------------------------------------------------------------- */

        PKA_FLIP_BIT0(LEN_ID_N_BITS, rP /* Res */, rP /* OpA */);
        PKA_FLIP_BIT0(LEN_ID_N_BITS, rQ /* Res */, rQ /* OpA */);

        uint32_t rGcd;
        uint32_t bit0P, bit0Q;

        /* remove common factors 2 from P-1, Q-1 to find odd */
        i = 0;
        do {
            PKA_SHR_FILL0(LEN_ID_N_BITS, rP, rP, 0 /* shift-1 */);
            PKA_SHR_FILL0(LEN_ID_N_BITS, rQ, rQ, 0 /* shift-1 */);
            PKA_READ_BIT0(LEN_ID_N_BITS, rP, bit0P);
            PKA_READ_BIT0(LEN_ID_N_BITS, rQ, bit0Q);
            i++;
        } while (bit0P == 0 && bit0Q == 0);

        /* D = (P-1) * (Q-1) / 2^i (removed only common divider 2^i) */
        PKA_2CLEAR(LEN_ID_MAX_BITS, rD); // ? RL
        PKA_MUL_LOW(LEN_ID_N_BITS, rD /* Res */, rP /* OpA */, rQ /* OpB */);
        PKA_SHL_FILL0(LEN_ID_N_BITS, rD, rD, i - 1);

        /* chose odd number as modulus for ModInv operation */
        if (bit0P == 1) {
            PKA_COPY(LEN_ID_N_BITS, r0 /* dst */, rP);
            rGcd = rQ;
        } else {
            PKA_COPY(LEN_ID_N_BITS, r0 /* dst */, rQ);
            rGcd = rP;
        }

        /* calculate GCD(rP,rQ) */
        PKA_MOD_INV(LEN_ID_N_BITS, rT /* temp */, rGcd);
        /* LCM = ((P-1)*(Q-1) / GCD) = rD/rGcd */
        PKA_DIV(LEN_ID_N_BITS, rLcm /* res: LCM */, rD, rGcd);

        /* ------------------------------------------------------------ */
        /* Because LCM may be even, but HW ModInw operation works     */
        /* only with odd modulus, we use reverse calculation as       *
         *  follows: D =  1/E mod LCM =                                */
        /*           = LCM - ((1/LCM mod E)*LCM - 1) / E              */
        /* ------------------------------------------------------------ */

        /* copy public exp E into r0 register */
        PKA_CopyDataIntoPkaReg(r0 /* dstReg */, LEN_ID_MAX_BITS, e_ptr /* src_ptr */, CALC_FULL_32BIT_WORDS(eSizeInBits));

        /* calc rT = 1/LCM mod E */
        PKA_COPY(LEN_ID_N_BITS, rP /* dst */, rLcm /* LCM */);                         /* rP used as temp */
        PKA_DIV(LEN_ID_N_BITS, rQ /* Res not used */, rP /* OpA=LCM */, r0 /* OpB=E */); /* rP = LCM mod E */

        PKA_MOD_INV(LEN_ID_N_BITS, rT /* Res */, rP /* OpB */); /* rT = 1/LCM mod E (E - odd, gcd(LCM,E)=1) */
        /* RL additional check need if E is not prime */
        PKA_COMPARE_IM_STATUS(LEN_ID_N_BITS, rP, 1 /* im */, stat);
        if (stat != 1) {
            Error = PKA_INTERNAL_ERROR;
            goto End;
        }

        /* rK = (rT*LCM - 1) / r0=E  */
        PKA_MUL_LOW(LEN_ID_N_PKA_REG_BITS, rT /* Res */, rT /* OpA */,
                    rLcm /* OpB */); /* Note: size of result < register size, because E is small */
        PKA_SUB_IM(LEN_ID_N_PKA_REG_BITS, rT /* Res */, rT /* OpA */, 1 /* OpB */);
        PKA_DIV(LEN_ID_N_PKA_REG_BITS, rD /* Res */, rT /* OpA */, r0 /* OpB */); /* rT = rT / e */
        PKA_SUB(LEN_ID_N_PKA_REG_BITS, rD /* Res */, rLcm /* OpA */, rD /* OpB */);

        /*    output the result value D */
        PKA_CopyDataFromPkaReg(d_ptr, 2 * primeSizeInWords, rD /* srcReg */);

        /* check that d > 2^(nlen/2) [FIPS 186-4, B.3.1] - very rare  *
         *  case.                                                      */
        for (i = 2 * primeSizeInWords - 1; i >= primeSizeInWords; i--) {
            isTrue = isTrue || (d_ptr[i] != 0);
        }
        if (!isTrue) {
            SaSi_PalMemSetZero(d_ptr, 2 * primeSizeInWords);
            Error = SaSi_RSA_GENERATED_PRIV_KEY_IS_TOO_LOW;
        }
    }

/*    End of the function  */
End:

    return Error;

} /* END OF PKA_CalculateNandD */

/* ********************************************************************************** */
/*
 * @brief The LLF_PKI_genKeyNonCrt generates a public and private RSA keys in NonCRT mode.
 *
 *    The function initializes the PKA according to used registers size, calculates
 *    keys components and finishes PKA operations.
 *
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param[in] e_ptr              - The pointer to the public exponent.
 * @param[in] eSizeInBits        - Size of public exponent in bits.
 * @param[in] n_ptr              - The pointer .
 * @param[in] eSizeInBits        - The public exponent size in bits.
 * @param[in] nLenInBits         - The required size of the key in bits.
 * @param[in] testsCount         - Count of Miller-Rabin tests. If testsCount = 0,
 *                                 then count of tests will be set automatically
 * @param[in]  Success_ptr       - The pointer to the flag of success generation of P,Q.
 * @param[out] p_ptr             - The pointer to the first factor.
 * @param[out] q_ptr             - The ponter to the second factor.
 * @param[out] n_ptr             - The pointer to the public modulus key.
 * @param[out] d_ptr             - The pointer to the private exponent (non CRT).
 * @param[in]  temp_ptr          - temp buffer of size 2 max RSA buffer size.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */

static SaSiError_t LLF_PKI_genKeyNonCrt(SaSi_RND_Context_t *rndContext_ptr, uint32_t *e_ptr, uint32_t eSizeInBits,
                                        uint32_t nSizeInBits, uint32_t *Success_ptr, uint32_t *p_ptr, uint32_t *q_ptr,
                                        uint32_t *n_ptr, uint32_t *d_ptr, uint32_t *temp_ptr)
{
    /* LOCAL DECLARATIONS */

    SaSiError_t Error = SaSi_OK;

    /* the primes P, Q size */
    uint32_t primeSizeInBits, primeSizeInWords;
    LlfRsaKgParams_t rsaKgPrimeTestParams;

    /* virtual pointers to PKA registers of single size */
    int8_t rE, rP, rQ;

    /* virtual pointers to single temp PKA registers */
    int8_t rSwap;

    /* PKA status */
    uint32_t status;
    uint32_t maxCountRegs = 20;

    /* FUNCTION LOGIC */

    /* ...................... initialize local variables ............................ */
    /* ------------------------------------------------------------------------------ */

    /* setting the primes P,Q length ; Note: the size of the modulus n is even */
    primeSizeInBits  = nSizeInBits / 2;
    primeSizeInWords = CALC_FULL_32BIT_WORDS(primeSizeInBits);

    /* initialize the success to 1 - success */
    *Success_ptr = SASI_FALSE;

    /* -------------------------------------------------------------------------------- */
    /* .................. executing the internal key generation ....................... */
    /* -------------------------------------------------------------------------------- */

    /* set virtual registers pointers */
    rE = regTemps[2]; /* 2 */
    rP = regTemps[3]; /* 3 */
    rQ = regTemps[4]; /* 4 */

    Error = PKA_InitAndMutexLock(nSizeInBits / 2, &maxCountRegs);
    if (Error != SaSi_OK) {
        return Error;
    }

    /* Set size if P, Q and auxiliary primes p1,p2,q1,q2 according  *
     *   to keysize. The following settings meet to  FIPS 186-4:    *
     *   5.1, C.3: Tab.C3.                                          */
    if (nSizeInBits <= SaSi_RSA_FIPS_KEY_SIZE_1024_BITS) {
        rsaKgPrimeTestParams.auxPrimesSizeInBits       = PKA_RSA_KEY_1024_AUX_PRIME_SIZE_BITS;
        rsaKgPrimeTestParams.auxPrimesMilRabTestsCount = PKA_RSA_KEY_1024_AUX_PRIME_RM_TST_COUNT /* 38 */;
        rsaKgPrimeTestParams.pqPrimesMilRabTestsCount  = PKA_RSA_KEY_1024_PQ_PRIME_RM_TST_COUNT /* 7 */;
    } else if (nSizeInBits <= SaSi_RSA_FIPS_KEY_SIZE_2048_BITS) {
        rsaKgPrimeTestParams.auxPrimesSizeInBits       = PKA_RSA_KEY_2048_AUX_PRIME_SIZE_BITS;
        rsaKgPrimeTestParams.auxPrimesMilRabTestsCount = PKA_RSA_KEY_2048_AUX_PRIME_RM_TST_COUNT /* 32 */;
        rsaKgPrimeTestParams.pqPrimesMilRabTestsCount  = PKA_RSA_KEY_2048_PQ_PRIME_RM_TST_COUNT /* 4 */;
    } else { /* if key size > 2048 */
        rsaKgPrimeTestParams.auxPrimesSizeInBits       = PKA_RSA_KEY_3072_AUX_PRIME_SIZE_BITS;
        rsaKgPrimeTestParams.auxPrimesMilRabTestsCount = PKA_RSA_KEY_3072_AUX_PRIME_RM_TST_COUNT /* 27 */;
        rsaKgPrimeTestParams.pqPrimesMilRabTestsCount  = PKA_RSA_KEY_3072_PQ_PRIME_RM_TST_COUNT /* 3 */;
    }

    /* ******************************************************************************* */
    /*                     CALCULATIONS WITH SHORT REGISTERS                          */
    /* init PKA on default mode according to P,Q operation size for creating P and Q. */
    /*  Note: All PKA memory shall be cleaned, insert nSizeInBits/2 => entry 0,       */
    /*        nSizeInBits/2+SASI_PKA_WORD_SIZE_IN_BITS => entry 1                     */
    /* ******************************************************************************* */

    /* set additional sizes into RegsSizesTable: */
    PKA_SetLenIds(nSizeInBits / 2, LEN_ID_PQ_BITS);
    PKA_SetLenIds(GET_FULL_OP_SIZE_BITS(nSizeInBits / 2), LEN_ID_PQ_PKA_REG_BITS);
    PKA_SetLenIds(rsaKgPrimeTestParams.auxPrimesSizeInBits, LEN_ID_AUX_PRIME_BITS);

    /* inforcing the prime candidates P,Q so the size of they is keySize/2  */
    /* ---------------------------------------------------------------------- */
    p_ptr[primeSizeInWords - 1] |= 0xC0000000;
    p_ptr[primeSizeInWords] = 0;
    p_ptr[0] |= 0x01;

    q_ptr[primeSizeInWords - 1] |= 0xC0000000;
    q_ptr[primeSizeInWords] = 0;
    q_ptr[0] |= 0x01;

    /* copy P,Q,E buffers into PKA registers */
    PKA_CopyDataIntoPkaReg(rP /* dstReg */, LEN_ID_MAX_BITS, p_ptr /* src_ptr */, primeSizeInWords);
    PKA_CopyDataIntoPkaReg(rQ /* dstReg */, LEN_ID_MAX_BITS, q_ptr /* src_ptr */, primeSizeInWords);
    PKA_CopyDataIntoPkaReg(rE /* dstReg */, LEN_ID_MAX_BITS, e_ptr /* src_ptr */, CALC_FULL_32BIT_WORDS(eSizeInBits));

    /* for debug */
#if defined LLF_PKI_PKA_DEBUG && defined DEBUG
#if (defined RSA_KG_NO_RND || defined RSA_KG_FIND_BAD_RND)
    PQindex = 0;
#endif
#endif

    /* find the first prime vector P */
    Error = llfRsaKgFindPrime(rndContext_ptr, rP, primeSizeInBits, rE, &rsaKgPrimeTestParams, regTemps + 5,
                              maxCountRegs - 5 /* tempsCount */, temp_ptr);

    if (Error != SaSi_OK) {
        goto End;
    }

    /* temp for debug */
#if defined LLF_PKI_PKA_DEBUG && defined DEBUG
#if (defined RSA_KG_NO_RND || defined RSA_KG_FIND_BAD_RND)
    PQindex = 1;
#endif
#endif

    /* find the secoond prime Q such that |P-Q| > 2^100 */
    /* -------------------------------------------------- */

    Error = llfRsaKgFindPrime(rndContext_ptr, rQ, primeSizeInBits, rE, &rsaKgPrimeTestParams, regTemps + 5,
                              maxCountRegs - 5 /* tempsCount */, temp_ptr);

    if (Error != SaSi_OK) {
        goto End;
    }

    /* ..... if Q is larger then P exchange the vectors - we want to have P>Q */
    PKA_SUB(LEN_ID_N_PKA_REG_BITS, RES_DISCARD, rP /* OpA */, rQ /* OpB */); /* reg extend */
    PKA_GET_StatusCarry(status);
    if (status == 0) { // means the calculated result is negative
        /* virtual */
        rSwap = rP;
        rP    = rQ;
        rQ    = rSwap;
    }

    PKA_CopyDataFromPkaReg(p_ptr /* dst_ptr */, primeSizeInWords, rP /* srcReg */);
    PKA_CopyDataFromPkaReg(q_ptr /* dst_ptr */, primeSizeInWords, rQ /* srcReg */);

    /* compare 100 MS bits of P and Q if them are equalled, then  *
     *  return to generation new values (X9.31)                    */
    if ((p_ptr[primeSizeInWords - 1] - q_ptr[primeSizeInWords - 1]) == 0 &&
        (p_ptr[primeSizeInWords - 2] - q_ptr[primeSizeInWords - 1]) == 0 &&
        (p_ptr[primeSizeInWords - 3] - q_ptr[primeSizeInWords - 1]) == 0 &&
        ((p_ptr[primeSizeInWords - 4] - q_ptr[primeSizeInWords - 1]) & 0xF0000000) == 0) {
        /* clean P,Q and goto new generation - extremely rare case */
        SaSi_PalMemSetZero(p_ptr, primeSizeInWords * sizeof(primeSizeInBits));
        SaSi_PalMemSetZero(q_ptr, primeSizeInWords * sizeof(primeSizeInBits));
    } else {
        /* calculate modulus n and private exponent d (if appropriate pointer is not NULL */
        Error = PKA_CalculateNandD(e_ptr, eSizeInBits, p_ptr, q_ptr, primeSizeInBits, n_ptr, d_ptr);

        if (Error == SaSi_OK) {
            *Success_ptr = SASI_TRUE;
        }
    }

End:
    PKA_FinishAndMutexUnlock(maxCountRegs);

    return Error;

} /* END OF LLF_PKI_genKeyNonCrt */

/* ********************************************************************************** */
/*
 * @brief The LLF_PKI_CalculateCrtParams calculates a private key on CRT mode
 *
 *
 * @param[in]  e_ptr             - The pointer to the public exponent.
 * @param[in]  eSizeInBits       - The public exponent size in bits.
 * @param[in]  nSizeInBits       - The size of the key modulus in bits.
 * @param[in]  p_ptr             - The first factor pointer.
 * @param[in]  q_ptr             - The second factor pointer.
 * @param[out] dp_ptr            - The private exponent for first factor.
 * @param[out] dq_ptr            - The private exponent for second factor.
 * @param[out] qinv_ptr          - The modular inverse of q relatively to modulus p.
 *
 *   ????? Assuming: - eSizeInBits < nSizeInBits/2.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
static SaSiError_t LLF_PKI_CalculateCrtParams(uint32_t *e_ptr, uint32_t eSizeInBits, uint32_t nSizeInBits,
                                              uint32_t *p_ptr, uint32_t *q_ptr, uint32_t *dp_ptr, uint32_t *dq_ptr,
                                              uint32_t *qInv_ptr)
{
    /* LOCAL DECLARATIONS */

    SaSiError_t Error = SaSi_OK;

    /* the primes P, Q size */
    uint32_t primeSizeInWords;

    /* virtual pointers to PKA registers of single size */
    int8_t r0, rP, rdP, rQ, rdQ, rQinv, rE;

    /* virtual pointers to single temp PKA registers */
    int8_t rT1, rT2, rT3, rT4, rT5;

    uint32_t maxCountRegs = 15;

    /* FUNCTION LOGIC */

    /* ...................... initialize local variables ............................ */
    /* ------------------------------------------------------------------------------ */

    /* setting the primes P,Q length ; Note: the size of the modulus n is even */
    primeSizeInWords = CALC_FULL_32BIT_WORDS(nSizeInBits / 2);

    /* ............... getting the hardware semaphore ..................... */
    /* -------------------------------------------------------------------- */

    Error = PKA_InitAndMutexLock(primeSizeInWords * SASI_BITS_IN_32BIT_WORD, &maxCountRegs);
    if (Error != SaSi_OK) {
        return Error;
    }

    /* set virtual registers pointers  */
    r0    = regTemps[0];  /* PKA_REG_N */
    rE    = regTemps[2];  /* 2 */
    rP    = regTemps[3];  /* 3 */
    rQ    = regTemps[4];  /* 4 */
    rdP   = regTemps[5];  /* 5 */
    rdQ   = regTemps[6];  /* 6 */
    rQinv = regTemps[7];  /* 7 */
    rT1   = regTemps[8];  /* 8 */
    rT2   = regTemps[9];  /* 9 */
    rT3   = regTemps[10]; /* 10 */
    rT4   = regTemps[11]; /* 11 */
    rT5   = regTemps[12]; /* 12 */

    /* copy data into PKA registers */
    /* ------------------------------ */
    PKA_CopyDataIntoPkaReg(rE /* dstReg */, LEN_ID_MAX_BITS, e_ptr /* src_ptr */, CALC_FULL_32BIT_WORDS(eSizeInBits));
    PKA_CopyDataIntoPkaReg(rP /* dstReg */, LEN_ID_MAX_BITS, p_ptr /* src_ptr */, primeSizeInWords);
    PKA_CopyDataIntoPkaReg(rQ /* dstReg */, LEN_ID_MAX_BITS, q_ptr /* src_ptr */, primeSizeInWords);

    /* -------------------------------------------------------------------------------- */
    /* ....................... calc dP , dQ, Qinv..................................... */
    /*      dP = E^-1 mod (P-1); dQ = E^-1 mod (Q-1); qInv = Q^-1 mod P;              */
    /* -------------------------------------------------------------------------------- */

    /* dQ: set mod register r0=Q-1 and perform ModInv operation */
    /* ----------------------------------------------------------- */
    PKA_FLIP_BIT0(LEN_ID_N_PKA_REG_BITS, r0 /* res */, rQ /* opA */);
    PKA_COPY(LEN_ID_MAX_BITS, rT1 /* ds */, rE /* src */);
    Error = PKA_ExecFullModInv(rT1 /* OpB */, rdQ /* Res */, rT2, rT3, rT4, rT5);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* dP: set mod register r0<=P-1 and perform ModInv operation */
    /* ----------------------------------------------------------- */
    PKA_FLIP_BIT0(LEN_ID_N_PKA_REG_BITS, r0 /* res */, rP /* dst */);
    PKA_COPY(LEN_ID_MAX_BITS, rT1 /* ds */, rE /* src */);
    Error = PKA_ExecFullModInv(rT1 /* OpB */, rdP /* Res */, rT2, rT3, rT4, rT5);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* Qinv: set mod register r0<=P and perform ModInv operation */
    /* ----------------------------------------------------------- */
    PKA_FLIP_BIT0(LEN_ID_N_PKA_REG_BITS, r0 /* Res */, r0 /* OpA */); /* r0= P */
    PKA_COPY(LEN_ID_MAX_BITS, rT1 /* dst */, rQ /* src */);
    PKA_MOD_INV(LEN_ID_N_BITS, rQinv /* Res */, rT1 /* OpB */);

    /* ----------------------------------------------------------- */
    /*    output of the result values dP,dQ,qInv                 */
    /* ----------------------------------------------------------- */

    PKA_CopyDataFromPkaReg(dp_ptr, primeSizeInWords, rdP /* srcReg */);

    PKA_CopyDataFromPkaReg(dq_ptr, primeSizeInWords, rdQ /* srcReg */);

    PKA_CopyDataFromPkaReg(qInv_ptr, primeSizeInWords, rQinv /* srcReg */);
End:
    PKA_FinishAndMutexUnlock(maxCountRegs);
    return Error;

} /* END OF PKA_CalculateCrtParams */

/* ********************************************************************************** */
/*
 * @brief The LLF_PKI_genKeyCrt generates a public and private keys on CRT mode
 *
 *
 * @param[in/out] rndContext_ptr - Pointer to the RND context buffer.
 * @param[in]  e_ptr             - The pointer to the public exponent.
 * @param[in]  eSizeInBits       - The public exponent size in bits.
 * @param[in]  nSizeInBits       - The size of the key modulus in bits.
 * @param[out] Success_ptr       - The pointer to index of success of the generation.
 * @param[out] p_ptr             - The first factor pointer. In - random number,
 *                                 out - prime (if successed).
 * @param[out] q_ptr             - The second factor pointer. In - random number,
 *                                 out - prime (if successed).
 * @param[out] n_ptr             - The pointer to the modulus of the key.
 * @param[out] dp_ptr            - The private exponent for first factor.
 * @param[out] dq_ptr            - The private exponent for second factor.
 * @param[out] qinv_ptr          - The modular inverse of q relatively to modulus p.
 *
 *    Assuming: - eSizeInBits < nSizeInBits/2.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
static SaSiError_t LLF_PKI_genKeyCrt(SaSi_RND_Context_t *rndContext_ptr, uint32_t *e_ptr, /* in */
                                     uint32_t eSizeInBits,                                /* in */
                                     uint32_t nSizeInBits,                                /* in */
                                     uint32_t *Success_ptr,                               /* out */
                                     uint32_t *p_ptr,                                     /* in/out */
                                     uint32_t *q_ptr,                                     /* in/out */
                                     uint32_t *n_ptr,                                     /* out */
                                     uint32_t *dp_ptr,                                    /* out */
                                     uint32_t *dq_ptr,                                    /* out */
                                     uint32_t *qInv_ptr,                                  /* out */
                                     uint32_t *temp_ptr)
{
    /* LOCAL DECLARATIONS */

    SaSiError_t Error = SaSi_OK;

    /* FUNCTION LOGIC */

    /* ...................... initialize local variables ............................ */
    /* ------------------------------------------------------------------------------ */

    /* initialize the success to 0 */
    *Success_ptr = SASI_FALSE;

    /* ......................Generate NonCRT private Key ............................ */
    /* ------------------------------------------------------------------------------ */
    Error = LLF_PKI_genKeyNonCrt(rndContext_ptr, e_ptr, /* in */
                                 eSizeInBits,           /* in */
                                 nSizeInBits,           /* in */
                                 Success_ptr,           /* out */
                                 p_ptr,                 /* out */
                                 q_ptr,                 /* out */
                                 n_ptr,                 /* out */
                                 NULL,                  /* out d_ptr - not needed */
                                 temp_ptr);

    if (Error != SaSi_OK || *Success_ptr != SASI_TRUE)

        return Error; /* return for generating new P,Q or to Stop */

    /* ..................Calculate CRT private Key parameters ....................... */
    /* ------------------------------------------------------------------------------ */

    Error = LLF_PKI_CalculateCrtParams(e_ptr, eSizeInBits, nSizeInBits, p_ptr, q_ptr, dp_ptr, dq_ptr, qInv_ptr);

    return Error;

} /* END OF LLF_PKI_genKeyCrt */

/* **************************************************************************************** */
/*
 * @brief This function is used to test a primality according to ANSI X9.42 standard.
 *
 *        The function calls the llfRsaKgPrimeTest function which performs said algorithm.
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param[in] P_ptr           - The pointer to the prime buff.
 * @param[in] sizeWords       - The prime size in words.
 * @param[in] rabinTestsCount - The count of Rabin-Miller tests repetition.
 * @param[in] isPrime         - The flag indicates primality:
 *                                  if is not prime - SASI_FALSE, otherwise - SASI_TRUE.
 * @param[in] TempBuff_ptr   - The temp buffer of minimum size:
 *                               - on HW platform  8*MaxModSizeWords,
 *                               - on SW platform  41*MaxModSizeWords.
 * @param[in] primeTestMode - primality testing mode (RSA or DH - defines how are performed some
 *            operations on temp buffers.
 */
SaSiError_t LLF_PKI_RSA_primeTestCall(SaSi_RND_Context_t *rndContext_ptr, uint32_t *P_ptr, int32_t sizeWords,
                                      int32_t rabinTestsCount, int8_t *isPrime_ptr, uint32_t *TempBuff_ptr,
                                      SaSi_RSA_DH_PrimeTestMode_t primeTestMode)
{
    /* LOCAL DECLARATIONS */

    /* the Error identifier */
    SaSiError_t Error;

    /* FUNCTION  LOGIC */

    TempBuff_ptr  = TempBuff_ptr;
    primeTestMode = primeTestMode;
    /* ............... getting the hardware semaphore ..................... */
    /* -------------------------------------------------------------------- */

    /* ------------------------------------------------------------------------ */
    /*               test the primality                                       */
    /* ------------------------------------------------------------------------ */
    Error =
        llfRsaKgPrimeTest(rndContext_ptr, P_ptr, sizeWords, rabinTestsCount, isPrime_ptr, primeTestMode, TempBuff_ptr);

    /* ---------------------------------------------------------------------- */
    /* .............. end of the function ................................... */
    /* ---------------------------------------------------------------------- */

    return Error;

} /* End of LLF_PKI_RSA_primeTestCall */

/* **************************************************************************************** */
/*
 * @brief This function generates a key pair
 *
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param[in] PubKey_ptr - the public key database.
 * @param[in] PrivKey_ptr - the private key database.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
SaSiError_t LLF_PKI_RSA_GenerateKeyPair(SaSi_RND_Context_t *rndContext_ptr, SaSiRSAPubKey_t *PubKey_ptr,
                                        SaSiRSAPrivKey_t *PrivKey_ptr, SaSi_RSAKGData_t *KeyGenData_ptr)
{
    /* LOCAL DECLARATIONS */

    /* error identification */
    SaSiError_t Error = SaSi_OK;

    /* the P,Q primitive pointers */
    uint32_t *P_ptr, *Q_ptr;
    uint32_t pqSizeWords;

    uint32_t Success;

    /* FUNCTION LOGIC */

    /* check that key size is not great, than allowed for Key Generation
       because pKA memory limit */
    if (PubKey_ptr->nSizeInBits > PKA_MAX_RSA_KEY_GENERATION_SIZE_BITS)
        return PKA_KG_UNSUPPORTED_KEY_SIZE;

    /* ............... initialize local variables ......................... */
    /* -------------------------------------------------------------------- */

    /* for avoid compiler warning */
    Success = 0;

    /* initialize the P,Q pointers to the buffers on the keygen data structure */
    P_ptr       = KeyGenData_ptr->KGData.p;
    Q_ptr       = KeyGenData_ptr->KGData.q;
    pqSizeWords = CALC_FULL_32BIT_WORDS(PubKey_ptr->nSizeInBits);

    /* ............... calling the Non CRT or CRT KeyGen functions ......... */
    /* --------------------------------------------------------------------- */

    do {
        if (PrivKey_ptr->OperationMode == SaSi_RSA_NoCrt) {
            Error = LLF_PKI_genKeyNonCrt(
                rndContext_ptr, PubKey_ptr->e, PubKey_ptr->eSizeInBits, PubKey_ptr->nSizeInBits, &Success, P_ptr, Q_ptr,
                PubKey_ptr->n, PrivKey_ptr->PriveKeyDb.NonCrt.d,
                ((LLF_pki_key_gen_db_t *)(KeyGenData_ptr->KGData.kg_buf.sasiRSAKGDataIntBuff))->temp);
        } else {
            Error =
                LLF_PKI_genKeyCrt(rndContext_ptr, PubKey_ptr->e, PubKey_ptr->eSizeInBits, PubKey_ptr->nSizeInBits,
                                  &Success, P_ptr, Q_ptr, PubKey_ptr->n, PrivKey_ptr->PriveKeyDb.Crt.dP,
                                  PrivKey_ptr->PriveKeyDb.Crt.dQ, PrivKey_ptr->PriveKeyDb.Crt.qInv,
                                  ((LLF_pki_key_gen_db_t *)(KeyGenData_ptr->KGData.kg_buf.sasiRSAKGDataIntBuff))->temp);
        }

        if (Error != SaSi_OK && Error != SaSi_RSA_GENERATED_PRIV_KEY_IS_TOO_LOW) {
            Success = false;
            goto End;
        }

#if !defined RSA_KG_NO_RND

        /* generate new P, Q candidates */
        /* ------------------------------ */
        while (!Success) {
            Error = SaSi_RSA_GenerateVectorInRangeX931(rndContext_ptr,
                                                       CALC_FULL_32BIT_WORDS(PubKey_ptr->nSizeInBits / 2), P_ptr);
            if (Error != SaSi_OK) {
                goto End;
            }

            Error = SaSi_RSA_GenerateVectorInRangeX931(rndContext_ptr,
                                                       CALC_FULL_32BIT_WORDS(PubKey_ptr->nSizeInBits / 2), Q_ptr);
            if (Error != SaSi_OK) {
                goto End;
            }
            /* check |p - q| > 2^((nSizeInBits/2)-100) */
            if (P_ptr[pqSizeWords - 1] - Q_ptr[pqSizeWords - 1] != 0 ||
                P_ptr[pqSizeWords - 2] - Q_ptr[pqSizeWords - 2] != 0 ||
                P_ptr[pqSizeWords - 3] - Q_ptr[pqSizeWords - 3] != 0 ||
                ((P_ptr[pqSizeWords - 4] - Q_ptr[pqSizeWords - 4]) >> 28) != 0) {
                break;
            }
        }
#endif

    } while (!Success);

    if (PrivKey_ptr->OperationMode == SaSi_RSA_NoCrt) {
        /* set the key source as external - a PATCH since 'D'  *
         *   is not decrypted in SK2   RL: ??                   */
        PrivKey_ptr->KeySource = SaSi_RSA_ExternalKey;

        /* set the length of d in bits */
        PrivKey_ptr->PriveKeyDb.NonCrt.dSizeInBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(
            PrivKey_ptr->PriveKeyDb.NonCrt.d, (uint16_t)(CALC_FULL_32BIT_WORDS(PubKey_ptr->nSizeInBits)));
    } else { /* CRT case */
        /* Load P,Q vectors */
        SaSi_PalMemCopy(PrivKey_ptr->PriveKeyDb.Crt.P, P_ptr, PubKey_ptr->nSizeInBits / 16);
        SaSi_PalMemCopy(PrivKey_ptr->PriveKeyDb.Crt.Q, Q_ptr, PubKey_ptr->nSizeInBits / 16);
    }

    /* load 'n' to the private */
    SaSi_PalMemCopy(PrivKey_ptr->n, PubKey_ptr->n, PubKey_ptr->nSizeInBits / 8);

End:

    return Error;
} /* END OF LLF_PKI_RSA_GenerateKeyPair */
