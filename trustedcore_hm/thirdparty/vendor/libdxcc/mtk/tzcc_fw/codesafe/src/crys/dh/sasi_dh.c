/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

#include "ssi_pal_mem.h"
#include "sasi_common.h"
#include "sasi_common_math.h"
#include "sasi_rnd.h"
#include "sasi_rnd_error.h"
#include "sasi_rnd_local.h"
#include "sasi_dh_error.h"
#include "sasi_dh.h"
#include "sasi_dh_kg.h"
#include "sasi_rsa_build.h"
#include "sasi_rsa_prim.h"
#include "llf_rsa.h"
#include "llf_rsa_public.h"
#include "llf_rsa_private.h"
#include "sasi_fips_defs.h"

/* *********************** Defines ***************************** */

/* *********************** Enums ******************************* */

/* *********************** macros ****************************** */

/* *********************** global data ********************************* */

/* *********************** Private Functions **************************** */
/* This function translates the DH hash modes into KDF hash modes */
static SaSi_KDF_HASH_OpMode_t MakeKDFHashMode(SaSi_DH_HASH_OpMode_t hashMode)
{
    SaSi_KDF_HASH_OpMode_t outMode;

    switch (hashMode) {
    case SaSi_DH_HASH_SHA1_mode:
        outMode = SaSi_KDF_HASH_SHA1_mode;
        break;
    case SaSi_DH_HASH_SHA224_mode:
        outMode = SaSi_KDF_HASH_SHA224_mode;
        break;
    case SaSi_DH_HASH_SHA256_mode:
        outMode = SaSi_KDF_HASH_SHA256_mode;
        break;
    case SaSi_DH_HASH_SHA384_mode:
        outMode = SaSi_KDF_HASH_SHA384_mode;
        break;
    case SaSi_DH_HASH_SHA512_mode:
        outMode = SaSi_KDF_HASH_SHA512_mode;
        break;
    default:
        outMode = SaSi_KDF_HASH_OpModeLast;
    }

    return outMode;
}

/* This function translates the DH deriveFunc enum to KDF derive func enum */
static SaSi_KDF_DerivFuncMode_t MakeKDFDeriveFuncMode(SaSi_DH_DerivationFunc_Mode deriveFunc)
{
    SaSi_KDF_DerivFuncMode_t outDeriveFunc;

    /* to avoid the problem of two same definitions in SaSi_DH_DerivationFunc_Mode */
    if (deriveFunc == SaSi_DH_Concat_Der_mode)
        return SaSi_KDF_ConcatDerivMode;

    switch (deriveFunc) {
    case SaSi_DH_ASN1_Der_mode:
        outDeriveFunc = SaSi_KDF_ASN1_DerivMode;
        break;
    case SaSi_DH_X963_DerMode:
        outDeriveFunc = SaSi_KDF_ConcatDerivMode;
        break;
    default:
        outDeriveFunc = SaSi_DH_DerivationFunc_ModeLast;
    }

    return outDeriveFunc;
}
/* *********************** Public Functions **************************** */

/* **************************************************************************************** */

/*
 * @brief _DX_DH_GeneratePubPrv_MTK has 2 functionalities:

           1. Randomly generates the Client private key Prv.
           2. Compute the Client public key which is
                  ClientPub = Generator ^ Prv mod Prime.

        Note: 1. All buffers arguments are represented in Big-Endian, i.e. MS byte is most left one.
              2. Assumed, that DH domain parameters (prime modulus P, generator G and order Q) are
                     trusted or checked before calling this function. The function partly checks only
                         pointers and sizes.

  @param[in] rndContext_ptr    - Pointer to the RND context buffer.
  @param[in] Generator_ptr     - Pointer to the Generator octet string.
  @param[in] GeneratorSize     - Size of the Generator String (in bytes). The size must be not great than PrimeSize.
  @param[in] Prime_ptr         - Pointer to the Prime octet string P.
  @param[in] PrimeSize         - Size of the Prime string (in bytes). The size must be not great than
                                  SaSi_DH_MAX_MOD_SIZE_IN_BYTES.
  @param[in] L             - Exact length of Private key in bits (relevant only for PKCS#3), defined
                                  by central authority. Must be not great, than Prime Size in bits.
                                   - If L != 0, then L must met to requirements:  1 <= L and 2^(L-1) <= P,
                                     Note: in our implementation required L >= 3.
                                     in this case force the private key size to be 2^(L-1) <= Prv < 2^l.
                                   - If L  = 0, then: 0 < Prv < P-1.
  @param[in] Q_ptr         - Pointer to the order Q of generator relevant only for ANSI X9.42):
                                        1 <= Prv <= q-1   or   1 < Prv < q-1.
  @param[in] QSize         - Size of the Q string in bytes. Relevant only for ANSI X9.42.
                                 The size must be not great than PrimeSize.
  @param[in] DH_mode        - Enumerator, declaring whether the mode is PKCS#3 or ANSI X9.42.
  @param[in] tmpPubKey_ptr    - A pointer to the public key structure. Used for the Exp operation.
                                                                  The structure doesn't need to be initialized.
  @param[in] tmpPrimeData_ptr     - A pointer to a structure containing internal buffers, the structure
                                  doesn't need to be initialized.
  @param[out] ClientPrvKey_ptr  - Pointer to the buffer for output the Private key octet string (Prv).
                                  In PKCS#3 this buffer should be at least the following size:
                                          - if L is provided the size of buffer: bufSizeBytes*8 >= L.
                                          - if L is NULL, then size of buffer >= PrimeSize.
                                  In X9.42 size of the buffer must be >= QSize.
  @param[in/out] ClientPrvKeySize_ptr - The user should provide the size of the buffer indicated by ClientPrvKey_ptr.
                                        The function returns the actual size in bytes of the Private key.
  @param[out] ClientPub_ptr     - A pointer to the Public key octet string.
  @param[in/out] ClientPubSize_ptr - The user should provide the size of the buffer indicated by ClientPub_ptr.
                                     This Buffer should be at least PrimeSize bytes.
                                     The function returns the actual size in bytes of the generated client public key.

  @return SaSiError_t - On success SaSi_OK is returned, on failure an ERROR as defined SaSi_DH_error.h:
                        SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;
                        SaSi_DH_INVALID_ARGUMENT_SIZE_ERROR;
                        SaSi_DH_INVALID_ARGUMENT_OPERATION_MODE_ERROR;
                        SaSi_DH_ARGUMENT_GENERATOR_SMALLER_THAN_ZERO_ERROR;
                        SaSi_DH_ARGUMENT_PRIME_SMALLER_THAN_GENERATOR_ERROR;
                        SaSi_DH_INVALID_L_ARGUMENT_ERROR;
                        SaSi_DH_ARGUMENT_PRV_SIZE_ERROR;
                        SaSi_DH_INVALID_ARGUMENT_OPERATION_MODE_ERROR;
 */
CEXPORT_C SaSiError_t _DX_DH_GeneratePubPrv_MTK(SaSi_RND_Context_t *rndContext_ptr,
                                                uint8_t *Generator_ptr,                     /* generator */
                                                uint16_t GeneratorSize, uint8_t *Prime_ptr, /* modulus */
                                                uint16_t PrimeSize, uint16_t L, /* Exact length of Private key in bits */
                                                uint8_t *Q_ptr,                 /* order/in */
                                                uint16_t QSize, SaSi_DH_OpMode_t DH_mode, /* in */
                                                SaSi_DHUserPubKey_t *tmpPubKey_ptr,       /* temp buff */
                                                SaSi_DHPrimeData_t *tmpPrimeData_ptr,     /* temp buff */
                                                uint8_t *ClientPrvKey_ptr,                /* out */
                                                uint16_t *ClientPrvKeySize_ptr,           /* in/out */
                                                uint8_t *ClientPub1_ptr,                  /* out */
                                                uint16_t *ClientPubSize_ptr)              /* in/out */

{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* temporary byte shift masks */
    uint8_t tmpByte, mask, mask1, shift;

    /* the vector 2^(L-1) size */
    uint16_t tmpSize;

    /* the comparing value, returned from the vectors compare */
    SaSi_COMMON_CmpCounter_t comp;

    SaSi_RND_State_t *rndState_ptr;
    SaSiRndGenerateVectWorkFunc_t RndGenerateVectFunc;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* check parameters */
    if (rndContext_ptr == NULL)
        return SaSi_RND_CONTEXT_PTR_INVALID_ERROR;
    if (rndContext_ptr->rndGenerateVectFunc == NULL)
        return SaSi_RND_GEN_VECTOR_FUNC_ERROR;

    rndState_ptr        = &(rndContext_ptr->rndState);
    RndGenerateVectFunc = rndContext_ptr->rndGenerateVectFunc;

    /* if an argument pointer is NULL return an error */
    if (Generator_ptr == NULL || Prime_ptr == NULL || ClientPrvKey_ptr == NULL || ClientPub1_ptr == NULL ||
        ClientPrvKeySize_ptr == NULL || ClientPubSize_ptr == NULL || tmpPubKey_ptr == NULL || tmpPrimeData_ptr == NULL)
        return SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;

    /* check DH mode */
    if (DH_mode > SaSi_DH_NumOfModes)
        return SaSi_DH_INVALID_ARGUMENT_OPERATION_MODE_ERROR;

    /* preliminary check of sizes */
    if (PrimeSize > SaSi_DH_MAX_MOD_SIZE_IN_BYTES || PrimeSize == 0)
        return SaSi_DH_INVALID_MODULUS_SIZE_ERROR;

    if (GeneratorSize == 0 || GeneratorSize > PrimeSize)
        return SaSi_DH_INVALID_ARGUMENT_SIZE_ERROR;

    if (*ClientPubSize_ptr < PrimeSize)
        return SaSi_DH_INVALID_PUBLIC_KEY_SIZE_ERROR;

    if (*ClientPrvKeySize_ptr < PrimeSize)
        return SaSi_DH_SECRET_KEY_SIZE_OUTPUT_ERROR;

    /* Check the the generator according to DH mode */
    if (DH_mode == SaSi_DH_PKCS3_mode)
        tmpByte = 0; /* for checking PKCS3 part 6.  0 < g < p */
    else             /* SaSi_DH_ANSI_X942_mode */
        tmpByte = 1; /* for checking ANSI_X942 part 7.2.  1 < g < p-1 */

    comp = SaSi_COMMON_CmpMsbUnsignedCounters(Generator_ptr, GeneratorSize, &tmpByte, 1);

    if (comp != SaSi_COMMON_CmpCounter1GraterThenCounter2)
        return SaSi_DH_ARGUMENT_GENERATOR_SMALLER_THAN_ZERO_ERROR;

    /* Compare the generator and the Prime: requested that g < P-1 */
    Prime_ptr[PrimeSize - 1] -= tmpByte; /* temporary p = p-1 */
    comp = SaSi_COMMON_CmpMsbUnsignedCounters(Generator_ptr, GeneratorSize, Prime_ptr, PrimeSize);

    if (comp != SaSi_COMMON_CmpCounter2GraterThenCounter1)
        return SaSi_DH_ARGUMENT_PRIME_SMALLER_THAN_GENERATOR_ERROR;

    /* repair P */
    Prime_ptr[PrimeSize - 1] += tmpByte;

    /* -------------------------------------------------------------------------------- */
    /*         DH public-private keys generation                                      */
    /* -------------------------------------------------------------------------------- */

    /* temporary set prime modulus into temp buffer in little endianness */
    // RL Endianness
    SaSi_COMMON_ReverseMemcpy((uint8_t *)tmpPrimeData_ptr->DataIn, Prime_ptr, PrimeSize);

    /* get actual size of prime in bits: min() used to prevent warnings */
    tmpSize = SaSi_MIN(PrimeSize * 8, (uint16_t)SaSi_COMMON_GetBytesCounterEffectiveSizeInBits(
                                          (uint8_t *)tmpPrimeData_ptr->DataIn, PrimeSize));

    /* correction of Prime_ptr pointer and Size for removing of not significant zero-bytes */
    if (PrimeSize - CALC_FULL_BYTES(tmpSize) > 0) {
        Prime_ptr += PrimeSize - CALC_FULL_BYTES(tmpSize);
        PrimeSize = CALC_FULL_BYTES(tmpSize);
    }

    switch (DH_mode) {
    case SaSi_DH_PKCS3_mode:
        /* ----------------------------------------------------------- *
    PKCS#3:  set x private random value according to following:
                           1) If L = 0: set    0 < x < P-1;
                           2) If L > 0: set  2^(L-1) <= x < 2^L ,
                                   where 2^(L-1) <= P.
          ----------------------------------------------------------- */
        if (L == 0) {
            /* Option 1: L is not provided - check the minimum size of the private key buffer */
            if (*ClientPrvKeySize_ptr < PrimeSize) {
                Error = SaSi_DH_ARGUMENT_PRV_SIZE_ERROR;
                goto End1;
            }

            /* random generation in range:  0 < x < P-1  (in little endian */
            Error = SaSi_RND_GenerateVectorInRange(rndContext_ptr, tmpSize /* rndSizeInBits */,
                                                   (uint8_t *)tmpPrimeData_ptr->DataIn /* maxVect */,
                                                   (uint8_t *)tmpPrimeData_ptr->DataOut /* out */);
            if (Error != SaSi_OK)
                goto End;

            /* reverse privKey to big endianness */
            SaSi_COMMON_ReverseMemcpy(ClientPrvKey_ptr, (uint8_t *)tmpPrimeData_ptr->DataOut, PrimeSize);

            /* private key size in bytes */
            *ClientPrvKeySize_ptr = PrimeSize;
        } else { /* Option 2:  0 and bit length of privKey must be exactly L bit * < L */
            /* check L and the minimum size of the private key buffer */
            if (tmpSize < L) {
                Error = SaSi_DH_INVALID_L_ARGUMENT_ERROR;
                goto End1;
            }
            if ((*ClientPrvKeySize_ptr) * 8 < L) {
                Error = SaSi_DH_ARGUMENT_PRV_SIZE_ERROR;
                goto End1;
            }

            /* actual private key size in bytes and shift value */
            *ClientPrvKeySize_ptr = CALC_FULL_BYTES(L);
            if (*ClientPrvKeySize_ptr > SaSi_DH_MAX_MOD_SIZE_IN_BYTES) {
                Error = SaSi_DH_ARGUMENT_PRV_SIZE_ERROR;
                goto End1;
            }
            shift = ((8 - (L & 7)) & 7);

            /* if L = modulus size, then generate random x with exact bit-size = L
               and value in range:  x < P * > 2^(L-1) */
            if (tmpSize == L) {
                mask  = 0x7F >> shift;
                mask1 = 0x80 >> shift;

                /* set temporary MSBit of modulus = 0 for generation random in range without MSbit */
                ((uint8_t *)tmpPrimeData_ptr->DataIn)[*ClientPrvKeySize_ptr - 1] &= mask;

                /* generate random in range */
                Error = SaSi_RND_GenerateVectorInRange(rndContext_ptr, tmpSize /* rndSizeInBits */,
                                                       (uint8_t *)tmpPrimeData_ptr->DataIn /* maxVect */,
                                                       (uint8_t *)tmpPrimeData_ptr->DataOut /* out */);

                if (Error != SaSi_OK)
                    goto End;

                /* set MSBit of random to 1 */
                ((uint8_t *)tmpPrimeData_ptr->DataIn)[*ClientPrvKeySize_ptr - 1] |= mask1;

                /* reverse privKey to big endianness */
                SaSi_COMMON_ReverseMemcpy(ClientPrvKey_ptr, (uint8_t *)tmpPrimeData_ptr->DataOut,
                                          *ClientPrvKeySize_ptr);
            }
            /* if L < modulus size, then generate random x of size L bits */
            else {
                /* random generation */
                Error = RndGenerateVectFunc(rndState_ptr, *ClientPrvKeySize_ptr, ClientPrvKey_ptr);

                if (Error != SaSi_OK)
                    goto End;

                /* set two appropriate high bits of privKey to 00..1 to met the requirement 2^(L-1) <= x < 2^L */
                if ((L & 7) > 0) {
                    mask                = 0xFF >> shift;
                    mask1               = 0x80 >> shift;
                    ClientPrvKey_ptr[0] = (ClientPrvKey_ptr[0] & mask) | mask1;
                }
                /* if( (L & 7) == 0 ) */
                else {
                    ClientPrvKey_ptr[0] |= 0x80;
                }
            }
        }

        break;

    case SaSi_DH_ANSI_X942_mode:
        /* ----------------------------------------------------------- *
                                      ANS X9.42:
                         1<= X <= q-1 or    1< X <= q-1
         -------------------------------------------------------------- */

        /* check order */
        if (Q_ptr == NULL) {
            Error = SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;
            goto End1;
        }

        if (QSize == 0 || QSize > PrimeSize) {
            Error = SaSi_DH_INVALID_ORDER_SIZE_ERROR;
            goto End1;
        }

        /* check client private key buffer size */
        if (*ClientPrvKeySize_ptr < QSize) {
            Error = SaSi_DH_ARGUMENT_PRV_SIZE_ERROR;
            goto End1;
        }

        /* set order Q into temp buffer in little endianness */
        SaSi_COMMON_ReverseMemcpy((uint8_t *)tmpPrimeData_ptr->DataIn, Q_ptr, QSize);

        /* get actual size in bits */
        tmpSize = (uint16_t)SaSi_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)tmpPrimeData_ptr->DataIn, QSize);
        /* private key size in bytes */
        *ClientPrvKeySize_ptr = CALC_FULL_BYTES(tmpSize);

        /* random in range:  1 < x < Q  (little endianness) */
        Error = SaSi_RND_GenerateVectorInRange(rndContext_ptr, tmpSize /* rndSizeInBits */,
                                               (uint8_t *)tmpPrimeData_ptr->DataIn /* maxVect */,
                                               (uint8_t *)tmpPrimeData_ptr->DataOut /* out */);
        if (Error != SaSi_OK)
            goto End;

        /* reverse privKey to big endianness */
        SaSi_COMMON_ReverseMemcpy(ClientPrvKey_ptr, (uint8_t *)tmpPrimeData_ptr->DataOut, *ClientPrvKeySize_ptr);

        break;

    default:
        Error = SaSi_DH_INVALID_ARGUMENT_OPERATION_MODE_ERROR;
        goto End1;
    }

    /* ----------------------------------------------------------- */
    /*           Create the public key                             */
    /* ----------------------------------------------------------- */

    /* Build the RSA PublKey data structure for the Exp operation, using RSA_Encrypt primitive */
    Error = SaSi_RSA_Build_PubKey_MTK(tmpPubKey_ptr, ClientPrvKey_ptr, *ClientPrvKeySize_ptr, Prime_ptr, PrimeSize);
    /* check error */
    if (Error != SaSi_OK) {
        goto End;
    }

    /* Call the exponent operation to calculate the ClientPub1 = Generator^privKey mod Prime */
    Error = SaSi_RSA_PRIM_Encrypt_MTK(tmpPubKey_ptr, tmpPrimeData_ptr, Generator_ptr, GeneratorSize, ClientPub1_ptr);
    if (Error != SaSi_OK) {
        goto End;
    }

    *ClientPubSize_ptr = PrimeSize;

End:

    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(ClientPrvKey_ptr, *ClientPrvKeySize_ptr);
        *ClientPrvKeySize_ptr = 0;
    }
End1:
    /* delete secure sensitive data */
    SaSi_PalMemSetZero(tmpPubKey_ptr, sizeof(SaSi_DHUserPubKey_t));
    SaSi_PalMemSetZero(tmpPrimeData_ptr, sizeof(SaSi_DHPrimeData_t));

    return Error;

} /* END OF _DX_DH_GeneratePubPrv_MTK function */

/* **************************************************************************************** */
/*
 * @brief SaSi_DH_GetSecretKey_MTK computes the shared secret key in the following computation:
                       SecretKey = ServerPubKey ^ ClientPrvKey mod Prime.

   Note:
        - All buffers arguments are represented in Big-Endian.
        - The actual size of private key in bits must be not less than 2 and not great,
          than actual size of Prime (modulus) in bits (in our implementation);
        - The user must obtain assurance of validity of the public key, using one of methods,
          described in ANS X9.42 paragraph 7.4.

  @param[in] ClientPrvKey_ptr     - Pointer to the private key octet string.
  @param[in] ClientPrvKeySize      - The Private key Size (in bytes).
  @param[in] ServerPubKey_ptr   - Pointer to the Server public key octet string
  @param[in] ServerPubKeySize   - The Server Public key Size (in bytes)
  @param[in] Prime_ptr         - Pointer to the Prime octet string.
  @param[in] PrimeSize         - Size of the Prime string.
  @param[in] tmprPubKey_ptr    - A pointer to the temp buffer (public key structure), used
                                  for the Exponentiation function; the struct doesn't need
                                  to be initialized.
  @param[in] tmpPrimeData_ptr     - A pointer to temp buffer (structure containing internal buffers);
                                  the structure doesn't need to be initialized.
  @param[out] SecretKey_ptr     - Pointer to output buffer for the secret key octet string.
                                This buffer should be at least of PrimeSize bytes.
  @param[in/out] SecretKeySize_ptr - The user should provide the size in bytes of the buffer indicated by SecretKey_ptr.
                                    The function will return the actual size in bytes of the output secret key.

  @return SaSiError_t - On success SaSi_OK is returned, on failure an ERROR as defined SaSi_DH_error.h:
                                            SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;
                                            SaSi_DH_INVALID_ARGUMENT_SIZE_ERROR;
                                            SaSi_DH_SECRET_KEY_SIZE_OUTPUT_ERROR;
*/
CEXPORT_C SaSiError_t SaSi_DH_GetSecretKey_MTK(uint8_t *ClientPrvKey_ptr, uint16_t ClientPrvKeySize,
                                               uint8_t *ServerPubKey_ptr, uint16_t ServerPubKeySize, uint8_t *Prime_ptr,
                                               uint16_t PrimeSize, SaSi_DHUserPubKey_t *tmpPubKey_ptr,
                                               SaSi_DHPrimeData_t *tmpPrimeData_ptr, uint8_t *SecretKey_ptr,
                                               uint16_t *SecretKeySize_ptr)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    SaSi_COMMON_CmpCounter_t cmpResult;
    uint8_t one = 1;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if an argument pointer is NULL return an error */
    if (ClientPrvKey_ptr == NULL || ServerPubKey_ptr == NULL || Prime_ptr == NULL || tmpPubKey_ptr == NULL ||
        tmpPrimeData_ptr == NULL || SecretKey_ptr == NULL || SecretKeySize_ptr == NULL)

        return SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;

    /* If an argument buffer size is zero return an error */
    if (PrimeSize == 0 || PrimeSize > SaSi_DH_MAX_MOD_SIZE_IN_BYTES || ClientPrvKeySize == 0 ||
        ClientPrvKeySize > PrimeSize || ServerPubKeySize == 0 || ServerPubKeySize > PrimeSize ||
        *SecretKeySize_ptr == 0 || *SecretKeySize_ptr < PrimeSize)
        return SaSi_DH_INVALID_ARGUMENT_SIZE_ERROR;

    /* 1. verifying that the private exponent is less than modulus, else subtract the modulus */
    cmpResult = SaSi_COMMON_CmpMsbUnsignedCounters(ClientPrvKey_ptr, ClientPrvKeySize, Prime_ptr, PrimeSize);

    if (cmpResult != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
        /* subtract modulus prime from private key and set result in temp buffer */
        SaSi_COMMON_SubtractMSBUint8Arrays(ClientPrvKey_ptr, ClientPrvKeySize, Prime_ptr, PrimeSize,
                                           (uint8_t *)tmpPrimeData_ptr->DataIn);

        /* build the Data for the Exp operation.
          Note: the user private key is set into public key structure */
        Error = SaSi_RSA_Build_PubKey_MTK(tmpPubKey_ptr, (uint8_t *)tmpPrimeData_ptr->DataIn, ClientPrvKeySize,
                                          Prime_ptr, PrimeSize);
    } else {
        /* build the Data for the Exp operation */
        Error = SaSi_RSA_Build_PubKey_MTK(tmpPubKey_ptr, ClientPrvKey_ptr, ClientPrvKeySize, Prime_ptr, PrimeSize);
    }

    if (Error != SaSi_OK)
        goto End;

    /* 3. create: Secret_key (or shared secret value) = Server_public_key *
     *  ^ Prv mod Prime                                                    */
    Error = SaSi_RSA_PRIM_Encrypt_MTK(tmpPubKey_ptr, /* Note: this is the private key */
                                      tmpPrimeData_ptr, ServerPubKey_ptr, ServerPubKeySize, SecretKey_ptr);

    if (Error != SaSi_OK)
        goto End;

    /* Secret key (shared secret value) size in bytes, including leading  *
     *  zeroes                                                             */
    *SecretKeySize_ptr = PrimeSize;

    /* Note: X9.42 7.5.1 requires that shared secret value != 1 */
    cmpResult = SaSi_COMMON_CmpMsbUnsignedCounters(&one, 1 /* size */, SecretKey_ptr, PrimeSize);

    if (cmpResult != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
        Error = SaSi_DH_ARGUMENT_BUFFER_SIZE_ERROR;
        goto End;
    }

End:
    /* delete secure sensitive data */
    SaSi_PalMemSetZero(tmpPubKey_ptr, sizeof(SaSi_DHUserPubKey_t));
    SaSi_PalMemSetZero(tmpPrimeData_ptr, sizeof(SaSi_DHPrimeData_t));

    return Error;
} /* END of SaSi_DH_GetSecretKey_MTK function */

/* ************************************************************* */
/*
 * @brief The function extracts the shared secret key data from shared secret
          value as follows:
                1. OPTIONAL - validate the correctness of the argument keys
                2. Call function SaSi_DH_GetSecretKey_MTK to calculate shared value.
                3. Call the Derivation function to derive a data key from the secret key.

        The actual APIs (macros) that will be used by the user are:
        SaSi_DH_X942_GetSecret_ASN1
        SaSi_DH_X942_GetSecret_Concat

        Note: All buffers arguments are represented in Big-Endian format

  @param[in] ClientPrvKey_ptr     - A pointer to the Private key octet string.
  @param[in] ClientPrvKeySize      - The Private key size, in bytes.
  @param[in] ServerPubKey_ptr   - A pointer to the Server public key octet string -
  @param[in] ServerPubKeySize   - The Server Public key size, in bytes.
  @param[in] Prime_ptr         - A pointer to the Prime octet string.
  @param[in] PrimeSize         - The size of the Prime string.
  @param[in] OtherInfo - The  pointer to structure , containing the data,
                shared by two entities of agreement and the data sizes.
                This argument is optional (if not needed - set it to NULL).
  @param[in] hashMode            - The hash function to be used.
  @param[in] DerFunc_mode     - The type of function to derive the secret key to the key data.
                                We use ASN.1-based function or Hash concatenation function mode.
  @param[in] tmpBuff_ptr    - A pointer to the DH temp buffer structure. Not initialized.
  @param[out] SecretKeyData_ptr - A pointer to the buffer for secret keying data.
  @param[in] SecretKeyDataSize - Specifies the derived Secret Key data size needed in bytes.
                                The size can't be larger than SaSi_DH_MAX_SIZE_OF_KEYING_DATA
                                (required by implementation).

  @return SaSiError_t - On success SaSi_OK is returned, on failure an ERROR as defined SaSi_DH_error.h:
                        SaSi_DH_SECRET_KEYING_DATA_SIZE_ILLEGAL_ERROR;

*/
CEXPORT_C SaSiError_t SaSi_DH_X942_GetSecretData_MTK(uint8_t *ClientPrvKey_ptr, uint16_t ClientPrvKeySize,
                                                     uint8_t *ServerPubKey_ptr, uint16_t ServerPubKeySize,
                                                     uint8_t *Prime_ptr, uint16_t PrimeSize,
                                                     SaSi_DH_OtherInfo_t *otherInfo_ptr, SaSi_DH_HASH_OpMode_t hashMode,
                                                     SaSi_DH_DerivationFunc_Mode DerivFunc_mode,
                                                     SaSi_DH_Temp_t *tmpBuff_ptr, uint8_t *SecretKeyingData_ptr,
                                                     uint16_t SecretKeyingDataSize)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    uint16_t SecretKeySize = PrimeSize;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* check pointers */
    if (tmpBuff_ptr == NULL || SecretKeyingData_ptr == NULL)
        return SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;

    /* check that the size of derived secret key is not NULL  */
    if (SecretKeyingDataSize == 0)
        return SaSi_DH_SECRET_KEYING_DATA_SIZE_ILLEGAL_ERROR;

    /* check that the keying data size is not too large  */
    if (SecretKeyingDataSize > SaSi_DH_MAX_SIZE_OF_KEYING_DATA)
        return SaSi_DH_SECRET_KEYING_DATA_SIZE_ILLEGAL_ERROR;

    /* Call the PKCS#3 get secret key function */
    Error = SaSi_DH_GetSecretKey_MTK(ClientPrvKey_ptr, ClientPrvKeySize, ServerPubKey_ptr, ServerPubKeySize, Prime_ptr,
                                     PrimeSize, &tmpBuff_ptr->UserPubKey, &tmpBuff_ptr->PrimeData,
                                     (uint8_t *)tmpBuff_ptr->TempBuff, &SecretKeySize);

    if (Error != SaSi_OK)
        goto ExitOnError;

    /* Let the keydataSize from the previous function determine the key data length in the next function */
    Error = SaSi_KDF_KeyDerivFunc_MTK((uint8_t *)tmpBuff_ptr->TempBuff, SecretKeySize, otherInfo_ptr,
                                      MakeKDFHashMode(hashMode), MakeKDFDeriveFuncMode(DerivFunc_mode),
                                      SecretKeyingData_ptr, SecretKeyingDataSize);

ExitOnError:

    SaSi_PalMemSetZero(tmpBuff_ptr, sizeof(SaSi_DH_Temp_t));

    return Error;

} /* END OF _DX_DH_X942_GetSecretData */

/* ************************************************************* */
/*
 * @brief SaSi_DH_X942_HybridGetSecretData_MTK computes the shared secret key as follows:
                1. OPTIONAL - validate the correctness of the argument keys
                2. SecretKey1 = ServerPubKey1 ^ ClientPrvKey1 mod Prime
                3. SecretKey2 = ServerPubKey2 ^ ClientPrvKey2 mod Prime
                3. Use of Derivation function to derive a secret data key from the 2 secret keys

        The actual APIs that will be used by the user are:
        SaSi_DH_X942_Hybrid_GetSecret_ASN1
        SaSi_DH_X942_Hybrid_GetSecret_Concat

        Note: All buffers arguments are represented in Big-Endian format.

  @param[in] ClientPrvKey_ptr1     - A pointer to the First Private key octet string number
  @param[in] ClientPrvKeySize1     - The First Private key Size, in bytes
  @param[in] ClientPrvKey_ptr2     - A pointer to the Second Private key octet string
  @param[in] ClientPrvKeySize2     - The Second Private key Size, in bytes
  @param[in] ServerPubKey_ptr1  - A pointer to the First Server public key octet string
  @param[in] ServerPubKeySize1  - The First Server Public key Size, in bytes
  @param[in] ServerPubKey_ptr2  - A pointer to the Second Server public key octet string
  @param[in] ServerPubKeySize2  - The Second Server Public key Size, in bytes
  @param[in] Prime_ptr         - A pointer to the Prime octet string
  @param[in] PrimeSize         - The size of the Prime string
  @param[in] OtherInfo - The  pointer to structure , containing the data,
                shared by two entities of agreement and the data sizes.
                This argument is optional (if not needed - set it to NULL).
  @param[in] hashMode        - The hash function to be used.
  @param[in] DerFunc_mode     - The type of function to derive the secret key to the key data.
                                  We use an ASN.1-based function or a Hash concatenation function mode.
  @param[in] tmpDhHybr_ptr      - A pointer to the DH hybrid temp byffer structure. Not initialized.
  @param[out] SecretKeyData_ptr - A pointer to the buffer for secret keying data.
  @param[in] SecretKeyDataSize - Specifies the derived Secret Key data size needed in bytes.
                                The size can't be 0 or larger than SaSi_DH_MAX_SIZE_OF_KEYING_DATA
                                (required by implementation).

  @return SaSiError_t - On success the value SaSi_OK is returned, and on failure an ERROR as defined in SaSi_DH_error.h:
                        SaSi_DH_SECRET_KEYING_DATA_SIZE_ILLEGAL_ERROR;
                        SaSi_DH_X942_HYBRID_SIZE1_BUFFER_ERROR;
                        SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;
                        SaSi_DH_INVALID_ARGUMENT_SIZE_ERROR;
                        SaSi_DH_INVALID_ARGUMENT_OPERATION_MODE_ERROR;
                        SaSi_DH_ARGUMENT_GENERATOR_SMALLER_THAN_ZERO_ERROR;
                        SaSi_DH_ARGUMENT_PRIME_SMALLER_THAN_GENERATOR_ERROR;
                        SaSi_DH_INVALID_L_ARGUMENT_ERROR;
                        SaSi_DH_ARGUMENT_PRV_SIZE_ERROR;
*/
CEXPORT_C SaSiError_t SaSi_DH_X942_HybridGetSecretData_MTK(
    uint8_t *ClientPrvKey_ptr1, uint16_t ClientPrvKeySize1, uint8_t *ClientPrvKey_ptr2, uint16_t ClientPrvKeySize2,
    uint8_t *ServerPubKey_ptr1, uint16_t ServerPubKeySize1, uint8_t *ServerPubKey_ptr2, uint16_t ServerPubKeySize2,
    uint8_t *Prime_ptr, uint16_t PrimeSize, SaSi_DH_OtherInfo_t *otherInfo_ptr, SaSi_DH_HASH_OpMode_t hashMode,
    SaSi_DH_DerivationFunc_Mode DerivFunc_mode, SaSi_DH_HybrTemp_t *tmpDhHybr_ptr, uint8_t *SecretKeyingData_ptr,
    uint16_t SecretKeyingDataSize)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* The assignment to Prime size is according to the real size of the buffer SecretKeyData_ptr */
    uint16_t SecretKeyDataSize1 = PrimeSize;
    uint16_t SecretKeyDataSize2 = PrimeSize;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* check pointers */
    if (tmpDhHybr_ptr == NULL || SecretKeyingData_ptr == NULL)
        return SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;

    /* check that the size of derived secret key is not NULL  */
    if (SecretKeyingDataSize == 0)
        return SaSi_DH_SECRET_KEYING_DATA_SIZE_ILLEGAL_ERROR;

    /* check that the keying data size is not too large  */
    if (SecretKeyingDataSize > SaSi_DH_MAX_SIZE_OF_KEYING_DATA)
        return SaSi_DH_SECRET_KEYING_DATA_SIZE_ILLEGAL_ERROR;

    /* Note: other input parameters will be shecked in called functions */

    /* get shared secret key (value) 1 */
    Error = SaSi_DH_GetSecretKey_MTK(ClientPrvKey_ptr1, ClientPrvKeySize1, ServerPubKey_ptr1, ServerPubKeySize1,
                                     Prime_ptr, PrimeSize, &tmpDhHybr_ptr->UserPubKey, &tmpDhHybr_ptr->PrimeData,
                                     (uint8_t *)&tmpDhHybr_ptr->TempBuff, &SecretKeyDataSize1);
    if (Error != SaSi_OK)
        goto End;

    /* get shared secret key (value) 2 */
    Error = SaSi_DH_GetSecretKey_MTK(ClientPrvKey_ptr2, ClientPrvKeySize2, ServerPubKey_ptr2, ServerPubKeySize2,
                                     Prime_ptr, PrimeSize, &tmpDhHybr_ptr->UserPubKey, &tmpDhHybr_ptr->PrimeData,
                                     (uint8_t *)&tmpDhHybr_ptr->TempBuff + SecretKeyDataSize1, &SecretKeyDataSize2);
    if (Error != SaSi_OK)
        goto End;

    /* Derive the secret key according to the secret key size and value   *
     *  key1||key2                                 */

    Error = SaSi_KDF_KeyDerivFunc_MTK(
        (uint8_t *)&tmpDhHybr_ptr->TempBuff, (uint16_t)(SecretKeyDataSize1 + SecretKeyDataSize2), otherInfo_ptr,
        MakeKDFHashMode(hashMode), MakeKDFDeriveFuncMode(DerivFunc_mode), SecretKeyingData_ptr, SecretKeyingDataSize);

End:
    SaSi_PalMemSetZero(tmpDhHybr_ptr, sizeof(SaSi_DH_HybrTemp_t));

    return Error;

} /* END OF SaSi_DH_X942_HybridGetSecretData_MTK */

/* *************************************************************************************** */
/*
 * @brief The function checks the obtained DH public key according to its domain
 *        parameters (see X9.42-2001)
 *
 * @param[out] modP_ptr           - The pointer to the modulus (prime) P.
 * @param[in]  modPSizeBytes      - The modulus size in bytes.
 * @param[in]  orderQ_ptr         - The pointer to the prime order Q of generator,
 * @param[in]  orderQSizeBytes    - The size of order of generator in bytes.
 * @param[in]  pubKey_ptr         - The pointer to the public key to be validated.
 * @param[in]  pubKeySizeBytes    - The public key size in bytes.
 * @param[in]  tempBuff_ptr       - The temp buffer for internal calculations.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure or if one or more domain
 *                       parameters are invalid the function returns a predefined error code.
 *
 *              Assuming: The DH domain parameters are valid.
 */
CEXPORT_C SaSiError_t SaSi_DH_CheckPubKey(uint8_t *modP_ptr,        /* in */
                                          uint32_t modPsizeBytes,   /* in */
                                          uint8_t *orderQ_ptr,      /* in */
                                          uint32_t orderQsizeBytes, /* in */
                                          uint8_t *pubKey_ptr,      /* in */
                                          uint32_t pubKeySizeBytes, /* in */
                                          SaSi_DH_Temp_t *tempBuff_ptr /* in */)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* size in bits of modulus P and order Q and public key */
    uint32_t modPsizeBits;
    uint32_t orderQsizeBits;
    uint32_t pubKeySizeBits;

    /* comparing result */
    int cmpRes;
    SaSi_COMMON_CmpCounter_t cmpCounters;
    SaSi_DHPubKey_t *tmpPubKey_ptr;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ------------------------------- */
    /* Step 1. Check input pointers   */
    /* ------------------------------- */

    /* check pointers: modP, generator and tempBuff. Note: other pointers may be NULL  */
    if (modP_ptr == NULL || orderQ_ptr == NULL || pubKey_ptr == NULL || tempBuff_ptr == NULL) {
        return SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;
    }
    /* temp public key buffer */
    tmpPubKey_ptr = (SaSi_DHPubKey_t *)((void *)&tempBuff_ptr->UserPubKey.PublicKeyDbBuff);

    /* ----------------------------------------------------------- */
    /* Step 2. Calculate and check the sizes of modulus and order */
    /* ----------------------------------------------------------- */
    /* preliminary check */
    if (modPsizeBytes > SaSi_DH_MAX_VALID_KEY_SIZE_VALUE_IN_BITS / 8)
        return SaSi_DH_INVALID_MODULUS_SIZE_ERROR;

    if (orderQsizeBytes > modPsizeBytes)
        return SaSi_DH_INVALID_ORDER_SIZE_ERROR;

    if (pubKeySizeBytes > modPsizeBytes)
        return SaSi_DH_INVALID_PUBLIC_KEY_SIZE_ERROR;

    /* convert input data into LSW arrays */
    /* ------------------------------------ */
    // RL - restrict zeroing
    SaSi_PalMemSetZero(tempBuff_ptr, sizeof(SaSi_DH_ExpTemp_t));

    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(tmpPubKey_ptr->n, modPsizeBytes, modP_ptr, modPsizeBytes);
    if (Error) {
        return Error;
    }

    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(tmpPubKey_ptr->e, modPsizeBytes, orderQ_ptr, orderQsizeBytes);
    if (Error) {
        goto End;
    }

    Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(tempBuff_ptr->PrimeData.DataIn, modPsizeBytes, pubKey_ptr,
                                                        pubKeySizeBytes);
    if (Error) {
        goto End;
    }

    /* calculate sizes in bits of input parameters */
    modPsizeBits =
        SaSi_MIN(8 * modPsizeBytes,
                 SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(tmpPubKey_ptr->n, (uint16_t)modPsizeBytes / 4));
    orderQsizeBits =
        SaSi_MIN(8 * orderQsizeBytes,
                 SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(tmpPubKey_ptr->e, (uint16_t)(orderQsizeBytes + 3) / 4));
    pubKeySizeBits =
        SaSi_MIN(8 * pubKeySizeBytes, SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(
                                          tempBuff_ptr->PrimeData.DataIn, (uint16_t)(pubKeySizeBytes + 3) / 4));

    /* check sizes */
    if (modPsizeBits < SaSi_DH_MIN_VALID_KEY_SIZE_VALUE_IN_BITS || modPsizeBits % 256 != 0 ||
        modPsizeBits > SaSi_DH_MAX_VALID_KEY_SIZE_VALUE_IN_BITS) {
        Error = SaSi_DH_INVALID_MODULUS_SIZE_ERROR;
        goto End;
    }

    if (orderQsizeBits < SaSi_DH_SEED_MIN_SIZE_IN_BITS || orderQsizeBits % 32 != 0) {
        Error = SaSi_DH_INVALID_ORDER_SIZE_ERROR;
        goto End;
    }

    if (pubKeySizeBits > modPsizeBits || pubKeySizeBits <= 1) {
        Error = SaSi_DH_INVALID_PUBLIC_KEY_SIZE_ERROR;
        goto End;
    }

    /* ----------------------------------------------------------- */
    /* Step 2. Check value of public key:   pubKey < P-1          */
    /*         Note: pubKey > 1 already is checked above          */
    /* ----------------------------------------------------------- */

    /* decrement modulus in temp buffer n (in little endianness). Note: the modulus is odd */
    tmpPubKey_ptr->n[0] -= 1;

    /* compare pub key saved in temp buff e to P-1 */
    cmpCounters = SaSi_COMMON_CmpLsWordsUnsignedCounters(tmpPubKey_ptr->e, /* counter1 - pubKey */
                                                         (uint16_t)(pubKeySizeBytes + 3) / 4,
                                                         tmpPubKey_ptr->n, /* counter2 - (P-1) */
                                                         (uint16_t)modPsizeBytes / 4);

    if (cmpCounters != SaSi_COMMON_CmpCounter2GraterThenCounter1) {
        Error = SaSi_DH_INVALID_PUBLIC_KEY_ERROR;
        goto End;
    }

    /* ---------------------------------------------------- */
    /* Step 4. Initialization of PubKey and PrivData      */
    /*         structures for exponentiation              */
    /* ---------------------------------------------------- */

    /* increment (revert) modulus in temp buffer n (in little endianness) */
    tmpPubKey_ptr->n[0] += 1;

    /* set modulus and exponent sizes in DH_PubKey structure  */
    tmpPubKey_ptr->nSizeInBits = modPsizeBits;
    tmpPubKey_ptr->eSizeInBits = orderQsizeBits;

    /*  initialize the H value in LLF of PubKey for exponentiation  */
    Error = LLF_PKI_RSA_InitPubKeyDb(tmpPubKey_ptr);

    if (Error != SaSi_OK)
        goto End;

    /* ----------------------------------------------------------- */
    /* Step 3. Calculate Res = Key ^ Q mod P , if Res == 1,      */
    /*         then key is valid, else non valid                 */
    /* ----------------------------------------------------------- */

    /* exponentiation DataOut = DataIn ^ exp mod n */
    Error = LLF_PKI_RSA_ExecPubKeyExp(tmpPubKey_ptr, &tempBuff_ptr->PrimeData);

    if (Error != SaSi_OK)
        goto End;

    /* set 1 to PubKey_ptr->n buffer (used as temp buffer) */
    SaSi_PalMemSetZero((uint8_t *)&tmpPubKey_ptr->n, modPsizeBytes);
    tmpPubKey_ptr->n[0] = 1;

    /* compare DataOut to 1: */
    cmpRes = SaSi_COMMON_CmpLsWordsUnsignedCounters(tempBuff_ptr->PrimeData.DataOut, modPsizeBytes / 4,
                                                    tmpPubKey_ptr->n, modPsizeBytes / 4);

    if (cmpRes != 0) { /* if Res != 1 */
        Error = SaSi_DH_INVALID_PUBLIC_KEY_ERROR;
        goto End;
    }

End:

    /* clean temp buffers */
    SaSi_PalMemSetZero(tempBuff_ptr, sizeof(SaSi_DH_Temp_t));

    return Error;
}
