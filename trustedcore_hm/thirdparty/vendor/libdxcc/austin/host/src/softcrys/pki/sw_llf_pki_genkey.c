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

#include "dx_pal_mem.h"
#include "crys_common_math.h"
#include "sw_llf_pki.h"
#include "sw_llf_pki_rsa.h"
#include "sw_llf_pki_error.h"
#include "llf_pki_util.h"
#ifdef DX_SOFT_KEYGEN
#include "ccsw_crys_rsa_types.h"
#else
#include "crys_pka_defs.h"
#include "crys_rsa_types.h"
#include "sw_crys_rsa_types_conv.h"
#endif

/* *********************** Defines **************************** */

/* canceling the PC-lint warning:
   while(1) */


#define LLF_GEN_KEY_FAIL         -1
#define LLF_GEN_KEY_COMPOSITE    0
#define LLF_GEN_KEY_PRIME        1
#define LLF_GEN_KEY_SMALL_PRIMES 303
#define PRIME_PRODUCT_NUM        (SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS)
#define PRIME_NUM                256

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

const uint16_t LLF_GEN_KEY_PRIMES[LLF_GEN_KEY_SMALL_PRIMES] = {
    2,    3,    5,    7,    11,   13,   17,   19,   23,   29,   31,   37,   41,   43,   47,   53,   59,   61,   67,
    71,   73,   79,   83,   89,   97,   101,  103,  107,  109,  113,  127,  131,  137,  139,  149,  151,  157,  163,
    167,  173,  179,  181,  191,  193,  197,  199,  211,  223,  227,  229,  233,  239,  241,  251,  257,  263,  269,
    271,  277,  281,  283,  293,  307,  311,  313,  317,  331,  337,  347,  349,  353,  359,  367,  373,  379,  383,
    389,  397,  401,  409,  419,  421,  431,  433,  439,  443,  449,  457,  461,  463,  467,  479,  487,  491,  499,
    503,  509,  521,  523,  541,  547,  557,  563,  569,  571,  577,  587,  593,  599,  601,  607,  613,  617,  619,
    631,  641,  643,  647,  653,  659,  661,  673,  677,  683,  691,  701,  709,  719,  727,  733,  739,  743,  751,
    757,  761,  769,  773,  787,  797,  809,  811,  821,  823,  827,  829,  839,  853,  857,  859,  863,  877,  881,
    883,  887,  907,  911,  919,  929,  937,  941,  947,  953,  967,  971,  977,  983,  991,  997,  1009, 1013, 1019,
    1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
    1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289,
    1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
    1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567,
    1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699,
    1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867,
    1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999
};

/* ************ Private function prototype ************** */

static int32_t SW_LLF_PKI_quickTest(uint32_t *p, uint32_t *temp_ptr, uint32_t len);
static int32_t SW_LLF_PKI_RabinMillerTest(uint32_t *p_ptr, uint32_t *temp_ptr, uint32_t len, uint32_t test);

static int32_t SW_LLF_PKI_primeTest(uint32_t *p_ptr, int32_t len, uint32_t *temp_ptr, /* Long buff */
                                    int32_t rabinTestsCount, CRYS_RSA_DH_PrimeTestMode_t primeTestMode);
static CRYSError_t SW_LLF_PKI_KG_X931_Jacobi(uint32_t *a_ptr, uint32_t *p_ptr, uint32_t pSizeInBits,
                                             uint32_t *temp1_ptr, uint32_t *temp2_ptr, uint32_t *temp3_ptr,
                                             uint32_t *temp4_ptr, uint32_t *temp5_DoubleBuff_ptr, int16_t *Result_ptr,
                                             CRYS_RSA_DH_PrimeTestMode_t primeTestMode);
static CRYSError_t SW_LLF_PKI_KG_X931_LucasPrimeTest(uint32_t *prime_ptr, uint32_t PrimeSizeInBits, uint32_t *temp1_ptr,
                                                     uint32_t *temp2_ptr, uint32_t *temp3_ptr, uint32_t *temp4_ptr,
                                                     uint8_t *SuccessCode_ptr,
                                                     CRYS_RSA_DH_PrimeTestMode_t primeTestMode);

/* *********************** Public Functions **************************** */

/* **********************************************************************************
 * @brief The SW_LLF_PKI_genKey calculates generates a public and private keys
 *
 *
 * @param[in] Prime1Random_ptr   - first prime random number - set at the beginning.
 * @param[in] Prime2Random_ptr   - second prime random number - set at the beginning.
 * @param[in] e_ptr              - The pointer to the public exponent.
 * @param[in] eLenInWords        - The public exponent size in words.
 * @param[out] n_ptr             - The pointer to the public modulus key.
 * @param[in] nLenInWords        - The required size of the key in words.
 * @param[out] d_ptr             - The pointer to the private exponent ( non CRT ).
 * @param[out] p_ptr             - The first factor pointer.
 * @param[out] q_ptr             - The second factor pointer.
 * @param[out] dp_ptr            - The first factor exp pointer only on CRT.
 * @param[out] dq_ptr            - The second factor exp pointer only on CRT.
 * @param[out] qinv_ptr          - The first coefficient - CRT
 * @param[in]  temp buffer       - temporary buffer.
 * @param[in]  isCrtMode         - PLS_TRUE - CRT mode , PLS_FALSE - non CRT mode.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */

CRYSError_t SW_LLF_PKI_genKey(uint32_t *e_ptr, uint32_t eLenInWords, uint32_t *n_ptr, uint32_t nLenInWords,
                              uint32_t *d_ptr, uint32_t *p_ptr, uint32_t *q_ptr, uint32_t *dp_ptr, uint32_t *dq_ptr,
                              uint32_t *qinv_ptr, uint32_t *temp_ptr, uint32_t isCrtMode)
{
    /* LOCAL INITIALIZATIONS */

    const uint32_t len  = nLenInWords / 2;
    uint32_t *e0_ptr    = temp_ptr; /* length 2*len */
    uint32_t *gcd_ptr   = temp_ptr + 2 * len;
    uint32_t *mem_ptr   = temp_ptr + 3 * len; /* long buff */
    uint32_t *phi_ptr   = temp_ptr + 4 * len; /* ?? 3*len : check may be 1 mod is redundant */
    uint32_t *dummy_ptr = temp_ptr + 6 * len;
    uint32_t *mem1_ptr  = temp_ptr + 8 * len; /* length 8*len */

    int32_t flag = LLF_GEN_KEY_FAIL;
    int32_t gcdFlag;
    int32_t i;
    int32_t exchange;
    int32_t tests;
    int32_t isPrime;

    /* FUNCTION LOGIC */

    /* According to IEEE P1363/D13 Annex A: A.15.2 (for 256,512 and 1024) */

    if (len * 32 < 512)
        tests = 17;
    else if (len * 32 < 1024)
        tests = 8;
    else
        tests = 4;

    DX_PAL_MemSetZero(e0_ptr, 2 * len * sizeof(uint32_t));
    DX_PAL_MemCopy(e0_ptr, e_ptr, eLenInWords * sizeof(uint32_t));

    /* enforcing p,q so the size of each one of them is the required key size /2
       in bits */
    p_ptr[len - 1] |= 0xC0000000UL;
    q_ptr[len - 1] |= 0xC0000000UL;
    p_ptr[len] = 0;
    q_ptr[len] = 0;

    /* setting the 1 LSB bits to '1' set the primitives as odd */
    p_ptr[0] |= 0x1;
    q_ptr[0] |= 0x1;

    /* ................ generate p .............. */

    while (flag == LLF_GEN_KEY_FAIL) {
        p_ptr[0]++;

        /* check that e and (p-1) are relatively prime */
        SW_LLF_PKI_gcd(p_ptr, e0_ptr, gcd_ptr, mem_ptr, len);

        gcd_ptr[0]--;
        p_ptr[0]++;
        gcdFlag = 0;

        for (i = 0; i < (int32_t)len; i++) { /* check if gcd is one */
            if (gcd_ptr[i]) {
                gcdFlag = 1;
                break;
            }
        }

        if (gcdFlag) /* If e and (p-1) are relatively prime promote p to p+2 mod 2^(2*len) */
            continue;

        isPrime = SW_LLF_PKI_primeTest(p_ptr, len, mem_ptr, /* temp4_ptr - 34 MaxModLen */
                                       tests,               /* rabinTestsCount */
                                       CRYS_RSA_PRIME_TEST_MODE);

        if (isPrime == LLF_GEN_KEY_PRIME)
            break;

    } /* end of generating P loop */

    /* ................ generate q ............... */

    while (flag == LLF_GEN_KEY_FAIL) {
        q_ptr[0]++;

        SW_LLF_PKI_gcd(q_ptr, e0_ptr, gcd_ptr, mem_ptr, len);

        gcd_ptr[0]--;
        q_ptr[0]++;
        gcdFlag = 0;

        for (i = 0; i < (int32_t)len; i++) {
            if (gcd_ptr[i]) {
                gcdFlag = 1;
                break;
            }
        }

        if (gcdFlag)
            continue;

        isPrime = SW_LLF_PKI_primeTest(q_ptr, len, mem_ptr, /* temp4_ptr - long buff */
                                       tests,               /* rabinTestsCount */
                                       CRYS_RSA_PRIME_TEST_MODE);

        if (isPrime == LLF_GEN_KEY_PRIME)
            break;

    } /* end of generating Q loop */

    /* -------------------------------------------------------------------------- */
    /* ensure that p>q  and p, q are different more than 100 MSbits ~ 3 MSWords  */
    exchange = 0;
    i        = (int32_t)len - 1;

    while (i >= 0) {
        if (p_ptr[i] > q_ptr[i])
            break;
        if (q_ptr[i] > p_ptr[i]) {
            exchange = 1;
            break;
        }
        i--;
    }

    if (i < (int32_t)len - 4) /*  p,q are not different enough */
        return SW_LLF_PKI_KEY_GENERATION_FAILURE;

    if (exchange) {
        for (i = 0; i < (int32_t)len; i++) {
            p_ptr[i] ^= q_ptr[i];
            q_ptr[i] ^= p_ptr[i];
            p_ptr[i] ^= q_ptr[i];
        }
    }

    /* calculate the public key- n */
    LLF_PKI_UTIL_ExecuteRMulOperation(p_ptr, (len + 1) * 32, q_ptr, n_ptr);
    p_ptr[0]--;
    q_ptr[0]--;

    /* calculate phi */
    LLF_PKI_UTIL_ExecuteRMulOperation(p_ptr, (len + 1) * 32, q_ptr, phi_ptr);

    /* calculate the private key - d */
    LLF_PKI_UTIL_InvMod(e0_ptr, phi_ptr, d_ptr, mem1_ptr, 2 * len);

    /* setting dP,dQ on CRT mode */
    if (isCrtMode) {
        LLF_PKI_UTIL_div(d_ptr, 2 * len, p_ptr, len, dp_ptr, dummy_ptr, mem1_ptr);

        LLF_PKI_UTIL_div(d_ptr, 2 * len, q_ptr, len, dq_ptr, dummy_ptr, mem1_ptr);
    }

    p_ptr[0]++;
    q_ptr[0]++;

    /* setting the Qinv on CRT mode */
    if (isCrtMode)
        /* calculate q^-1 mod p */
        LLF_PKI_UTIL_InvMod(q_ptr, p_ptr, qinv_ptr, mem1_ptr, len);

    return CRYS_OK;

} /* END OF SW_LLF_PKI_genKey */

/* *********************** Private Functions **************************** */

/* *************************************************************************
 * ==================================================================
 * Function name: SW_LLF_PKI_quickTest
 *
 * Description: This function tests if input number is divided by small primes.
 *
 * Author: Victor Elkonin
 *
 * Last revision: 1.00.00
 *
 * Update History:
 * Rev 1.00.00, Date 28 September 2004, By Victor Elkonin: Initial version.
 * ========================================================================
 */
static int32_t SW_LLF_PKI_quickTest(uint32_t *p, uint32_t *temp_ptr, uint32_t len)
{
    /* LOCAL INITIALIZATIONS */

    uint32_t *dummy_ptr   = temp_ptr;
    uint32_t *residue_ptr = temp_ptr + len;
    int i;
    uint32_t modLen = 1;
    uint32_t numLen = len;

    /* FUNCTION LOGIC */

    for (i = 1; i < LLF_GEN_KEY_SMALL_PRIMES; i++) {
        uint32_t temp = LLF_GEN_KEY_PRIMES[i];

        LLF_PKI_UTIL_div(p, numLen, &temp, modLen, residue_ptr, dummy_ptr, temp_ptr + len + 1);

        if (!residue_ptr[0])
            return LLF_GEN_KEY_COMPOSITE;
    }

    return LLF_GEN_KEY_PRIME;

} /* END OF SW_LLF_PKI_quickTest */

/* ********************************************************************
 * ==================================================================
 * Function name: SW_LLF_PKI_RabinMillerTest
 *
 * Description: This function perform Rabin-Miller test on an input number.
 *
 * Author: Victor Elkonin
 *
 * Last Revision: 1.00.00
 *
 * Method: IEEE P1363/D13 Annex A15.1 and A15.2
 *
 *  Note: Temp buffer must be at last 41 max mod length size
 *        (according to windows=5, used in exponentiation)
 *
 * Update History:
 * Rev 1.00.00, Date 28 September 2004, By Victor Elkonin: Initial version.
 * ========================================================================
 */
static int32_t SW_LLF_PKI_RabinMillerTest(uint32_t *p_ptr, uint32_t *temp_ptr, uint32_t len, uint32_t test)
{
    /* LOCAL INITIALIZATIONS */

    uint32_t i, j = 0, k, t;
    uint32_t mlen;
    uint32_t a          = 0;
    uint32_t digit      = p_ptr[0] - 1;
    uint32_t *m_ptr     = temp_ptr;
    uint32_t *b_ptr     = temp_ptr + len;
    uint32_t *z_ptr     = temp_ptr + 2 * len;
    uint32_t *z2_ptr    = temp_ptr + 3 * len;
    uint32_t *dummy_ptr = temp_ptr + 5 * len;

    /* FUNCTION LOGIC */

    /* set the tested number to 1 + 2^a * m */
    /* find a: */
    for (i = 0; i < len;) {
        for (j = 0; j < 32; j++) {
            if (digit & 1)
                break;
            a++;
            digit >>= 1;
        }

        if (j < 32)
            break;

        digit = p_ptr[++i];
    }

    /* build m: */
    mlen = len - i;
    for (k = 0; i < len - 1; k++) {
        m_ptr[k] = p_ptr[i++] >> j;
        m_ptr[k] |= p_ptr[i] << (32 - j);
    }

    m_ptr[k] = p_ptr[i] >> j;

    DX_PAL_MemSetZero(b_ptr, len * sizeof(uint32_t));
    b_ptr[0] = 2;

    for (t = 0; t < test; t++) {
        LLF_PKI_UTIL_CalcExponent(b_ptr, len * 32, m_ptr, mlen * 32, p_ptr, len * 32,
                                  min(5, PKI_EXP_SLIDING_WINDOW_MAX_VALUE),
                                  temp_ptr + 7 * len, /* ?? 5*len may be restricted 2 len buffer */
                                  temp_ptr + 3 * len, z_ptr);

        j = 0;
        while (1) {
            int flag = 0;
            if (z_ptr[0] == 1)
                flag = 1;
            else if (z_ptr[0] == (p_ptr[0] - 1))
                flag = 2;
            if (flag == 1) {
                for (i = 1; i < len; i++)
                    if (z_ptr[i]) {
                        flag = 0;
                        break;
                    }
            }
            if (flag == 2) {
                for (i = 1; i < len; i++)
                    if (z_ptr[i] - p_ptr[i]) {
                        flag = 0;
                        break;
                    }
            }
            if (flag == 2)
                break;
            if (flag == 1) {
                if (j == 0)
                    break;
                else
                    return LLF_GEN_KEY_COMPOSITE;
            }

            if (++j == a)
                return LLF_GEN_KEY_COMPOSITE;

            LLF_PKI_UTIL_ExecuteRMulOperation(z_ptr, len * 32, z_ptr, z2_ptr);

            LLF_PKI_UTIL_div(z2_ptr, 2 * len, p_ptr, len, z_ptr, dummy_ptr, temp_ptr + 7 * len);
        }
        b_ptr[0] += 3;
    }

    return LLF_GEN_KEY_PRIME;

} /* END OF SW_LLF_PKI_RabinMillerTest */

/* *********************************************************************
 * ==================================================================
 * Function name: SW_LLF_PKI_gcd
 *
 * Description: This function calculates the GCD of two numbers.
 *
 * Computes a = gcd(b, c).
 * Assumes b > c.
 *
 * Author: Victor Elkonin
 *
 * Last revision: 1.00.00
 *
 * Method: IEEE P1363/D13 Annex A15.1 and A15.2
 *
 * Update History:
 * Rev 1.00.00, Date 28 September 2004, By Victor Elkonin: Initial version.
 * ========================================================================
 */

void SW_LLF_PKI_gcd(uint32_t *b_ptr, uint32_t *c_ptr, uint32_t *result_ptr, uint32_t *temp_ptr, uint32_t len)
{
    /* LOCAL INITIALIZATIONS */

    uint32_t *u_ptr     = temp_ptr;
    uint32_t *v_ptr     = temp_ptr + len;
    uint32_t *w_ptr     = temp_ptr + 2 * len;
    uint32_t *dummy_ptr = temp_ptr + 3 * len;
    uint32_t *mem_ptr   = temp_ptr + 4 * len;
    uint32_t i;

    /* FUNCTION LOGIC */

    DX_PAL_MemCopy(u_ptr, b_ptr, len * sizeof(uint32_t));
    DX_PAL_MemCopy(v_ptr, c_ptr, len * sizeof(uint32_t));

    while (1) {
        LLF_PKI_UTIL_div(u_ptr, len, v_ptr, len, w_ptr, dummy_ptr, mem_ptr);

        for (i = 0; i < len; i++)
            if (w_ptr[i])
                break;

        if (i == len)
            break;
        DX_PAL_MemCopy(u_ptr, v_ptr, len * sizeof(uint32_t));
        DX_PAL_MemCopy(v_ptr, w_ptr, len * sizeof(uint32_t));
    }

    DX_PAL_MemCopy(result_ptr, v_ptr, len * sizeof(uint32_t));

    return;

} /* END OF SW_LLF_PKI_gcd */

/* ********************************************************************************** */
/* @brief This function executes Jacobi functions .
 *
 * if there is such a vector b that satisfies the condition b^2 = a mod p the result is 1
 * if there is no such vector the result is -1
 *
 * @param[in] a_ptr - The pointer to the base vector.
 * @param[in] p_ptr - The pointer to the prime to be tested (the modulus).
 * @param[in] pSizeInBits - the size of vector p in bits.
 * @param[out] Result_ptr - a pointer to the result var (1,0,-1) as described in the description.
 * @param[in] PrimeSizeInBits - The prime size in bits.
 * @param[in] temp1_ptr,temp2_ptr,temp3_ptr,temp4_ptr - temporary buffers , must contain 1024 + 32 bits.
 * @param[in] primeTestMode - primality testing mode (RSA or DH - defines how are performed some
 *            operations on temp buffers.
 * @param[in] temp5_DoubleBuff_ptr - double temp buffer must contain 2048 + 32 bits
 *
 *     Note: On DH mode size of all temp buffers must be two times greater,
 *           than above described for RSA mode.
 */
CRYSError_t SW_LLF_PKI_KG_X931_Jacobi(uint32_t *a_ptr, uint32_t *p_ptr, uint32_t pSizeInBits, uint32_t *temp1_ptr,
                                      uint32_t *temp2_ptr, uint32_t *temp3_ptr, uint32_t *temp4_ptr,
                                      uint32_t *temp5_DoubleBuff_ptr, int16_t *Result_ptr,
                                      CRYS_RSA_DH_PrimeTestMode_t primeTestMode)
{
    /* FUNCTION DECLERATIONS */

    int16_t k, s;
    uint8_t residue;
    uint32_t pSizeInBytes;
    uint32_t pSizeInWords;

    /* the recursive buffers */
    uint32_t *a1_ptr, *p1_ptr;

    /* a temp pointer */
    uint32_t *temp_ptr;

    /* result compare */
    CRYS_COMMON_CmpCounter_t ResCompare;

    /* size of temp buffers which must be cleared */
    uint32_t tempBuffSizeToClean;

    /* FUNCTION LOGIC */

    /* .......................... initialize local variables ............................... */
    /* ------------------------------------------------------------------------------------- */

    /* set size of temp buffers which must be cleared */
    if (primeTestMode == CRYS_RSA_PRIME_TEST_MODE) {
        tempBuffSizeToClean = (SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2) * sizeof(uint32_t);
    } else { /* DH mode */
        tempBuffSizeToClean = (SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS) * sizeof(uint32_t);
    }

    /* ........... clearing the temp buffers ............... */
    DX_PAL_MemSetZero(temp2_ptr, tempBuffSizeToClean);
    DX_PAL_MemSetZero(temp3_ptr, tempBuffSizeToClean);

    /* setting the vector sizes */
    pSizeInBytes = pSizeInBits / 8;

    if (pSizeInBits % 8)

        pSizeInBytes++;

    pSizeInWords = pSizeInBits / 32;

    if (pSizeInBits % 32)

        pSizeInWords++;

    /* setting the recursive inner vector pointers to the buffers */
    a1_ptr = temp2_ptr;
    p1_ptr = temp3_ptr;

    /* copy the input vectors */
    DX_PAL_MemCopy(a1_ptr, a_ptr, pSizeInBytes);
    DX_PAL_MemCopy(p1_ptr, p_ptr, pSizeInBytes);

    /* initialize the result as 1 ( default ) */
    *Result_ptr = 1;

    /* ..................... if a is 1 return the result 1 ...................... */
    /* -------------------------------------------------------------------------- */

    /* step 3.  if a1 == 1, return - we have done */
    DX_PAL_MemSetZero(temp1_ptr, tempBuffSizeToClean);

    temp1_ptr[0] = 1;
    ResCompare =
        CRYS_COMMON_CmpLsbUnsignedCounters((uint8_t *)temp1_ptr, pSizeInBytes, (uint8_t *)a1_ptr, pSizeInBytes);

    if (ResCompare == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical)

        return CRYS_OK;

    /* ..................... do loop for finding the Jacobi ..................... */
    /* -------------------------------------------------------------------------- */

    do {
        /* step 1.  if a == 0, return the result 0 */
        DX_PAL_MemSetZero(temp1_ptr, tempBuffSizeToClean);
        ResCompare =
            CRYS_COMMON_CmpLsbUnsignedCounters((uint8_t *)temp1_ptr, pSizeInBytes, (uint8_t *)a1_ptr, pSizeInBytes);

        if (ResCompare == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical) {
            *Result_ptr = 0;
            return CRYS_OK;
        }

        /* step 2 divide out larger power of two */
        k = 0;
        while (!(a1_ptr[0] & 0x01)) {
            CRYS_COMMON_DivideVectorBy2(a1_ptr, pSizeInWords);
            k++;
        }

        /* initialize s as 0 */
        s = 0;

        /* step 3.  if e is even set s=1 */
        if ((k & 1) == 0) {
            s = 1;
        } else {
            /* else set s=1 if p = 1/7 (mod 8) or s=-1 if p = 3/5 (mod 8) */
            residue = (uint8_t)p1_ptr[0] & 7;

            if (residue == 1 || residue == 7) {
                s = 1;
            } else if (residue == 3 || residue == 5) {
                s = -1;
            }
        }

        /* step 4.  if p == 3 (mod 4) *and* a1 == 3 (mod 4) then s = -s */
        if (((p1_ptr[0] & 3) == 3) && ((a1_ptr[0] & 3) == 3)) {
            s = -s;
        }

        /* step 5 : update the result pointer */
        *Result_ptr *= s;

        /* step 6.  if a1 == 1, return - we have done */
        temp1_ptr[0] = 1;
        ResCompare =
            CRYS_COMMON_CmpLsbUnsignedCounters((uint8_t *)temp1_ptr, pSizeInBytes, (uint8_t *)a1_ptr, pSizeInBytes);

        if (ResCompare == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical)

            return CRYS_OK;

        /* p1 = p1 mod a1 - the result is at temp5_DoubleBuff_ptr */
        LLF_PKI_UTIL_div(p1_ptr, pSizeInWords, a1_ptr, pSizeInWords, temp4_ptr, /* modRes */
                         temp1_ptr,                                             /* divRes */
                         temp5_DoubleBuff_ptr);                                 /* tempBuff: size=2*modLen */

        DX_PAL_MemCopy(p1_ptr, temp4_ptr, pSizeInBytes);

        /* exchange P1 & A1 */
        temp_ptr = p1_ptr;
        p1_ptr   = a1_ptr;
        a1_ptr   = temp_ptr;

    } while (1); /* end of do loop */

    /*    return CRYS_OK; */

} /* END OF SW_LLF_PKI_KG_X931_Jacobi */

/* ******************************************************************************************** */
/*     NOTE: !!!!! As yet the function SW_LLF_PKI_KG_X931_LucasPrimeTest is not debugged and not used */
/*
 * @brief This function executes the Rabin- Miller test according to the the X931 standard .
 *
 * @param[in,out] PrimePtr - The pointer to the prime to be tested buffer.
 * @param[in] PrimeSizeInBits - The prime size in bits.
 * @SuccessCode_ptr[out] - the success code : 0 - the test failed , 1 the test passed.
 * @param[in] primeTestMode - primality testing mode (RSA or DH - defines how are performed some
 *            operations on temp buffers.
 *
 *      NOTE:  - The max size supported is 2048 bits.
 *             - For RSA mode the size of temp buffers 1,2,3 must be minimum
 * SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS. and size of temp buffer 4 must be minimum
 * 2*SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS.
 *             - For DH mode the size of temp buffers 1,2,3 must be minimum
 * 2*SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS. and size of temp buffer 4 must be minimum
 * 4*SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */

CRYSError_t SW_LLF_PKI_KG_X931_LucasPrimeTest(uint32_t *prime_ptr, uint32_t PrimeSizeInBits, uint32_t *temp1_ptr,
                                              uint32_t *temp2_ptr, uint32_t *temp3_ptr, uint32_t *temp4_ptr,
                                              uint8_t *SuccessCode_ptr, CRYS_RSA_DH_PrimeTestMode_t primeTestMode)
{
    /* FUNCTION DECLERATIONS */

    /* the pointers to d vectors */
    uint32_t *d_ptr, *dmon_ptr;

    /* vectors */
    uint32_t *k_ptr, *u_ptr, *v_ptr, *uNew_ptr, *vNew_ptr;
    uint32_t *temp_ptr, *tempA_ptr, *tempB_ptr, *swapVecTemp_ptr;

    /* vector sizes */
    uint32_t kSizeInBits;

    /* internal variables */
    uint32_t d_abs;
    uint32_t d_is_positive;

    /* size variables */
    uint32_t PrimeSizeInWords;
    uint32_t PrimeSizeInBytes;

    /* Jacobi result */
    int16_t JaccobiSucessCode;

    /* compare identifier */
    CRYS_COMMON_CmpCounter_t ResCompare;

    /* loop variable */
    int32_t i;

    /* size of temp buffers which must be cleared */
    uint32_t tempBuffSizeToClean;

    /* middle of temp buffer position  */
    uint32_t tempBuffMiddle;

    /* mod0tag -specific parameters for Montgomery multiplication */
    LLF_PKI_UTIL_MonMulInputParam_t LLFSpesificParams;

    /* the Error identifier */
    CRYSError_t Error;

    /* FUNCTION LOGIC */

    /* ........................... initialize local variables ....................... */
    /* ------------------------------------------------------------------------------ */

    /* set size of temp buffers which must be cleared (bytes), and middle position of the buffer (words) */
    if (primeTestMode == CRYS_RSA_PRIME_TEST_MODE) {
        tempBuffSizeToClean = (SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS) * sizeof(uint32_t);
        tempBuffMiddle      = (SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS / 2);
    } else { /* DH mode */
        tempBuffSizeToClean = (SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 2) * sizeof(uint32_t);
        tempBuffMiddle      = (SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS);
    }

    /* set the size variables (adding one word to since the Montgomery result (A*B) might be 1p or 2p more */
    PrimeSizeInWords = (PrimeSizeInBits + 31) / 32;
    PrimeSizeInBytes = (PrimeSizeInBits + 7) / 8;

    /* ......................... clear the temp buffers ............................. */
    DX_PAL_MemSetZero(temp1_ptr, tempBuffSizeToClean);
    DX_PAL_MemSetZero(temp2_ptr, tempBuffSizeToClean);
    DX_PAL_MemSetZero(temp3_ptr, tempBuffSizeToClean);
    DX_PAL_MemSetZero(temp4_ptr, 3 * tempBuffSizeToClean);

    /* allocate a buffer  d  */
    d_ptr = temp1_ptr;

    /* calculate mod0tag for MonMult operations */
    Error = LLF_PKI_UTIL_StartMonMulOperation(prime_ptr, &LLFSpesificParams);

    if (Error != CRYS_OK)

        return Error;

    /* ............................ setting the d vector .............................. */
    /* -------------------------------------------------------------------------------- */

    /* on this loop we set the 'd' vector :
       temp1_ptr is used for the d,H vectors.
       temp2_ptr is used for the d_abs subtraction
       temp3_ptr , temp4_ptr are temp buffers used for the Jacobi */
    for (d_abs = 5, d_is_positive = 1;; d_abs += 2, d_is_positive = !d_is_positive) {
        if (d_is_positive)

            d_ptr[0] = d_abs;

        else {
            DX_PAL_MemSetZero(temp2_ptr, tempBuffSizeToClean);

            temp2_ptr[0] = d_abs;

            CRYS_COMMON_SubtractUintArrays(prime_ptr, temp2_ptr, PrimeSizeInWords, d_ptr);
        }

        Error = SW_LLF_PKI_KG_X931_Jacobi(d_ptr, prime_ptr, PrimeSizeInBits, temp3_ptr, &temp3_ptr[tempBuffMiddle],
                                          temp4_ptr, &temp4_ptr[tempBuffMiddle], temp2_ptr, &JaccobiSucessCode,
                                          primeTestMode);
        if (Error != CRYS_OK)

            return Error;

        if (JaccobiSucessCode == -1)

            break;

    } /* end of loop for finding d */

    /* .... convert the d vector to Montgomery ( dmon = d * H ) */
    /* .... dmon is stored on temp2 buffer */

    dmon_ptr = temp2_ptr;

    /* set temp3 = d * 2^(32*PrimeSizeInWords) */
    DX_PAL_MemSetZero((uint8_t *)temp3_ptr, 2 * 4 * PrimeSizeInWords);
    DX_PAL_MemCopy((uint8_t *)temp3_ptr + 4 * PrimeSizeInWords, d_ptr, 4 * PrimeSizeInWords);

    /* calculate: dmon = temp2 mod prime */
    LLF_PKI_UTIL_div(temp3_ptr,                 /* numerator - in */
                     2 * PrimeSizeInWords,      /* numerator size - in */
                     prime_ptr,                 /* modulus - in */
                     PrimeSizeInWords,          /* modulus len words - in */
                     dmon_ptr,                  /* modulus result - out */
                     &dmon_ptr[tempBuffMiddle], /* div result - temp */
                     temp4_ptr);                /* temp buffer (2*modLen)- temp */

    /* ............................ init vectors for the test loop ................. */
    /* ----------------------------------------------------------------------------- */

    /* dmon is stored on temp2_ptr */
    /* temp is stored on temp2_ptr[middle] */
    /* k is stored on temp1_ptr[middle] */
    /* tempA_ptr stored on temp1_ptr */
    /* u is stored on temp3_ptr */
    /* uNew is stored on temp3_ptr[middle] */
    /* v is stored on temp4_ptr */
    /* vNew is stored on temp4_ptr[middle] */

    /* allocate the vectors */
    k_ptr     = &temp1_ptr[tempBuffMiddle];
    temp_ptr  = &temp2_ptr[tempBuffMiddle];
    u_ptr     = temp3_ptr;
    uNew_ptr  = &temp3_ptr[tempBuffMiddle];
    v_ptr     = temp4_ptr;
    vNew_ptr  = &temp4_ptr[tempBuffMiddle];
    tempA_ptr = &temp4_ptr[4 * tempBuffMiddle];
    tempB_ptr = &temp4_ptr[2 * tempBuffMiddle];

    /* *** init u and v to Mon(1) ** */

    /* set 1 * 2^(32*PrimeSizeInWords) in temp 1 buff */
    DX_PAL_MemSetZero(temp1_ptr, 4 * PrimeSizeInWords);
    temp1_ptr[PrimeSizeInWords] = 1;

    /* calculate: u = temp3 mod prime */
    LLF_PKI_UTIL_div(temp1_ptr,            /* numerator - in */
                     PrimeSizeInWords + 1, /* numerator size */
                     prime_ptr,            /* modulus - in */
                     PrimeSizeInWords,     /* modulus len words */
                     u_ptr,                /* modulus result - out */
                     temp_ptr,             /* div result - not used temp */
                     temp4_ptr);           /* temp buffer (2*modLen)- in */

    /* clean temp4 buffer */
    DX_PAL_MemSetZero(temp4_ptr, 6 * tempBuffMiddle * sizeof(uint32_t));

    /* copy u to v */
    DX_PAL_MemCopy(v_ptr, u_ptr, PrimeSizeInBytes);

    /* k = n + 1 */
    DX_PAL_MemSetZero(temp_ptr, tempBuffMiddle * sizeof(uint32_t));
    temp_ptr[0] = 1;
    CRYS_COMMON_Add2vectors(temp_ptr, prime_ptr, PrimeSizeInWords + 1, k_ptr);

    /* set 0 to one word after u_ptr high word */
    u_ptr[PrimeSizeInWords] = 0;

    /* set the size of k in bits */
    kSizeInBits = CRYS_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)k_ptr, PrimeSizeInBytes);

    /* ..................... the test loop execution ............................ */
    /* -------------------------------------------------------------------------- */

    for (i = (int32_t)(kSizeInBits - 2); i >= 0; --i) {
        /* a bit value */
        uint32_t bit;

        /* normalize u,v */
        ResCompare = CRYS_COMMON_CmpLsbUnsignedCounters((uint8_t *)u_ptr, PrimeSizeInBytes + 1, (uint8_t *)prime_ptr,
                                                        PrimeSizeInBytes);

        if (ResCompare == CRYS_COMMON_CmpCounter1GraterThenCounter2) {
            CRYS_COMMON_SubtractUintArrays(u_ptr, prime_ptr, PrimeSizeInWords + 1, u_ptr);
        }

        ResCompare = CRYS_COMMON_CmpLsbUnsignedCounters((uint8_t *)v_ptr, PrimeSizeInBytes + 1, (uint8_t *)prime_ptr,
                                                        PrimeSizeInBytes);

        if (ResCompare == CRYS_COMMON_CmpCounter1GraterThenCounter2) {
            CRYS_COMMON_SubtractUintArrays(v_ptr, prime_ptr, PrimeSizeInWords + 1, v_ptr);
        }
        /* clear extra byte from uNw and Vnew buffers */
        uNew_ptr[PrimeSizeInWords]  = 0;
        vNew_ptr[PrimeSizeInWords]  = 0;
        temp_ptr[PrimeSizeInWords]  = 0;
        tempB_ptr[PrimeSizeInWords] = 0;

        /* uNew = uv */
        LLF_PKI_UTIL_ExecuteMonMulOperation(u_ptr, v_ptr, prime_ptr, PrimeSizeInBits, tempA_ptr, uNew_ptr,
                                            &LLFSpesificParams);
        /* vNew = v^2 */
        LLF_PKI_UTIL_ExecuteMonMulOperation(v_ptr, v_ptr, prime_ptr, PrimeSizeInBits, tempA_ptr, vNew_ptr,
                                            &LLFSpesificParams);
        /* temp = u^2 */
        LLF_PKI_UTIL_ExecuteMonMulOperation(u_ptr, u_ptr, prime_ptr, PrimeSizeInBits, tempA_ptr, temp_ptr,
                                            &LLFSpesificParams);
        /* tempB = d * u^2 */
        tempB_ptr[PrimeSizeInWords] = 0;
        LLF_PKI_UTIL_ExecuteMonMulOperation(temp_ptr, dmon_ptr, prime_ptr, PrimeSizeInBits, tempA_ptr, tempB_ptr,
                                            &LLFSpesificParams);
        /* Vnew = (v^2 + d*u^2)/2 */
        CRYS_COMMON_Add2vectors(vNew_ptr, tempB_ptr, PrimeSizeInWords + 1, vNew_ptr);

        /* if the vector is odd add the prime */
        if (vNew_ptr[0] & 0x01)

            CRYS_COMMON_Add2vectors(vNew_ptr, prime_ptr, PrimeSizeInWords + 1, vNew_ptr);

        CRYS_COMMON_DivideVectorBy2(vNew_ptr, PrimeSizeInWords + 1);

        /* swap v,vNew */
        swapVecTemp_ptr = vNew_ptr;
        vNew_ptr        = v_ptr;
        v_ptr           = swapVecTemp_ptr;

        /* swap u,uNew */
        swapVecTemp_ptr = uNew_ptr;
        uNew_ptr        = u_ptr;
        u_ptr           = swapVecTemp_ptr;

        bit = CRYS_COMMON_GET_BIT_VAL_FROM_WORD_ARRAY(k_ptr, i);

        if (bit) {
            /* normalize u */
            ResCompare = CRYS_COMMON_CmpLsbUnsignedCounters((uint8_t *)u_ptr, PrimeSizeInBytes + 1,
                                                            (uint8_t *)prime_ptr, PrimeSizeInBytes);

            if (ResCompare == CRYS_COMMON_CmpCounter1GraterThenCounter2)

                CRYS_COMMON_SubtractUintArrays(u_ptr, prime_ptr, PrimeSizeInWords + 1, u_ptr);

            /* uNew = (u+v)/2 */
            CRYS_COMMON_Add2vectors(v_ptr, u_ptr, PrimeSizeInWords + 1, uNew_ptr);

            /* if the vector is odd add the prime */
            if (uNew_ptr[0] & 0x01)

                CRYS_COMMON_Add2vectors(uNew_ptr, prime_ptr, PrimeSizeInWords + 1, uNew_ptr);

            CRYS_COMMON_DivideVectorBy2(uNew_ptr, PrimeSizeInWords + 1);

            /* vNew = (u*d+v)/2 */
            vNew_ptr[PrimeSizeInWords] = 0; /* clean high word of buffer */

            LLF_PKI_UTIL_ExecuteMonMulOperation(u_ptr, dmon_ptr, prime_ptr, PrimeSizeInBits, tempA_ptr, vNew_ptr,
                                                &LLFSpesificParams);

            CRYS_COMMON_Add2vectors(v_ptr, vNew_ptr, PrimeSizeInWords + 1, vNew_ptr);

            /* if the vector is odd add the prime */
            if (vNew_ptr[0] & 0x01)

                CRYS_COMMON_Add2vectors(vNew_ptr, prime_ptr, PrimeSizeInWords + 1, vNew_ptr);

            CRYS_COMMON_DivideVectorBy2(vNew_ptr, PrimeSizeInWords + 1);

            /* swap v,vNew */
            swapVecTemp_ptr = vNew_ptr;
            vNew_ptr        = v_ptr;
            v_ptr           = swapVecTemp_ptr;

            /* swap u,uNew */
            swapVecTemp_ptr = uNew_ptr;
            uNew_ptr        = u_ptr;
            u_ptr           = swapVecTemp_ptr;

        } /* end of bit is set to 1 */

    } /* end of loop */

    /* set Success code = 0 */
    *SuccessCode_ptr = 0;

    /* if the result of u is equal to N or to 0 return success code = 1 else 0 */
    DX_PAL_MemSetZero((uint8_t *)temp_ptr, PrimeSizeInBytes);
    ResCompare =
        CRYS_COMMON_CmpLsbUnsignedCounters((uint8_t *)u_ptr, PrimeSizeInBytes, (uint8_t *)prime_ptr, PrimeSizeInBytes);

    if (ResCompare == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical)

        *SuccessCode_ptr = 1;

    else { /* compare to 0 */
        ResCompare = CRYS_COMMON_CmpLsbUnsignedCounters((uint8_t *)u_ptr, PrimeSizeInBytes + 1, (uint8_t *)temp_ptr,
                                                        PrimeSizeInBytes);

        if (ResCompare == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical)

            *SuccessCode_ptr = 1;
    }

    return CRYS_OK;

} /* END OF SW_LLF_PKI_KG_X931_LucasPrimeTest */

/* *********************************************************************************** */
/*
 * Function name: SW_LLF_PKI_primeTest
 *
 * Description: This function tests primality of an input number.
 *
 * Author: R.Levin
 *
 * Last Revision: 1.00.00
 *
 * Method: Test by small primes, then test by Rabin-Miller. If mode = DH,
 *         then test also by Lucas-Lehmer.
 *
 * @param[in] p_ptr           - The pointer of tested number.
 * @param[in] len             - The number size in words.
 * @param[in] temp_ptr        - The pointer to temp buffer4.
 *                              Size -41*SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS
 * @param[in] rabinTestsCount - The count of RabinMiller tests.
 * @param[in] primeTestMode   - Enum variable, defining which testing mode
 *                              to perform: for RSA or for DH.
 * @return  value defining is the tested number probably prime:
 *          1 - prime, 0 - not prime, other - error code.
 *
 * Note: 1. If primeTestMode is CRYS_RSA_PRIME_TEST_MODE, then:
 *           - rabinTestsCount is not needed  and may be any value.
 *
 * Update History:
 * Rev 1.00.00, Date 20 November 2007.
 * ========================================================================
 */
int32_t SW_LLF_PKI_primeTest(uint32_t *p_ptr, int32_t len, uint32_t *temp_ptr, /* Long buff */
                             int32_t rabinTestsCount, CRYS_RSA_DH_PrimeTestMode_t primeTestMode)
{
    /* LOCAL DECLARATIONS */

    int32_t isPrime;
    uint32_t PrimeSizeInBits;

    /* INITIALIZATIONS */

    /* FUNCTION LOGIC */

    if ((p_ptr[0] & 1) == 0)
        return LLF_GEN_KEY_COMPOSITE;

    isPrime = SW_LLF_PKI_quickTest(p_ptr, temp_ptr, (uint32_t)len);

    if (isPrime != LLF_GEN_KEY_PRIME)
        return isPrime;

    isPrime = SW_LLF_PKI_RabinMillerTest(p_ptr, temp_ptr, (uint32_t)len, (uint32_t)rabinTestsCount);

    if (isPrime != LLF_GEN_KEY_PRIME)
        return isPrime;

    if (primeTestMode == CRYS_DH_PRIME_TEST_MODE) {
        uint32_t *temp1_ptr, *temp2_ptr, *temp3_ptr;

        temp1_ptr = temp_ptr + 2 * SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS;
        temp2_ptr = temp1_ptr + 2 * SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS;
        temp3_ptr = temp2_ptr + 2 * SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS;

        /* calculate PrimeSizeInBits */
        PrimeSizeInBits = CRYS_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)p_ptr, 4 * len);

        SW_LLF_PKI_KG_X931_LucasPrimeTest(p_ptr, PrimeSizeInBits, temp_ptr, temp1_ptr, temp2_ptr, temp3_ptr,
                                          (uint8_t *)&isPrime, primeTestMode);
    }

    return isPrime;

} /* END OF SW_LLF_PKI_primeTest */

/* ******************************************************************************************
 * @brief This function is used to test a primality according to ANSI X9.42 standard.
 *
 *        The function calls the SW_LLF_PKI_primeTest function which performs said algorithm.
 *
 * @param[in] P_ptr           - The pointer to the prime buff.
 * @param[in] sizeWords       - The prime size in words.
 * @param[in] rabinTestsCount - The count of Rabin-Miller tests repetition.
 * @param[in] isPrime         - The flag indicates primality:
 *                                  if is not prime - PLS_FALSE, otherwise - PLS_TRUE.
 * @param[in] TempBuff_ptr   - The temp buffer of minimum size:
 *                               - on HW platform  8*MaxModSizeWords,
 *                               - on SW platform  41*MaxModSizeWords.
 * @param[in] primeTestMode - primality testing mode (RSA or DH - defines how are performed some
 *            operations on temp buffers.
 */
CRYSError_t SW_LLF_PKI_PrimeTestCall(uint32_t *P_ptr, int32_t sizeWords, int32_t rabinTestsCount, int8_t *isPrime_ptr,
                                     uint32_t *TempBuff_ptr, CRYS_RSA_DH_PrimeTestMode_t primeTestMode)
{
    /* FUNCTION  DEFINITIONS */

    /* FUNCTION  LOGIC */

    *isPrime_ptr = (int8_t)SW_LLF_PKI_primeTest(P_ptr, (int32_t)sizeWords, TempBuff_ptr, /* 41*MaxModSizeWords */
                                                rabinTestsCount, primeTestMode);

    return CRYS_OK;
}
