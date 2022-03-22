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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CRYS_API

#include "dx_pal_types.h"
#include "dx_pal_mem.h"
#include "cc_plat.h"
#include "crys_aes.h"
#include "crys_aes_error.h"
#include "crys_bypass_api.h"
#include "cipher.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "key_buffer.h"
#include "crys_common_math.h"
#include "cc_acl.h"
#include "dx_error.h"
#include "crys_context_relocation.h"

/* *********************** Global Data ********************************* */

/* Define CRYS_AES_WRAP_IV according to AES WRAP standard rfc3394 and
   CMLA v1.0-05-12-21 definitions */
#define CRYS_AES_WRAP_RFC3394_IV 0xA6

#ifdef DX_CC_TEE
#define CRYS_AES_WRAP_BUFF_OF_WORDS (sizeof(struct sep_ctx_cipher) / 2 + 3)
#else
#define CRYS_AES_WRAP_BUFF_OF_WORDS sizeof(struct sep_ctx_cipher) / 4
#endif
#define CRYS_AES_WRAP_BUFF_OF_WORDS_IN_BYTES (CRYS_AES_WRAP_BUFF_OF_WORDS * sizeof(uint32_t))
/* ************ Private function prototype ***************************** */

static uint8_t GlobalInCacheBuffer[MAX_NUM_HW_QUEUES][CRYS_AES_WRAP_DATA_MAX_SIZE_IN_BYTES +
                                                      CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES] DX_NO_INIT_VARIABLE;
static uint8_t GlobalOutCacheBuffer[MAX_NUM_HW_QUEUES][CRYS_AES_WRAP_DATA_MAX_SIZE_IN_BYTES +
                                                       CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES] DX_NO_INIT_VARIABLE;

/* !
 * Converts Symmetric Adaptor return code to CRYS error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CRYSError_t one of CRYS_* error codes defined in crys_error.h
 */
static CRYSError_t SymAdaptor2CrysAesWrapErr(int symRetCode, uint32_t errorInfo)
{
    switch (symRetCode) {
    case DX_RET_UNSUPP_ALG:
        return CRYS_AES_IS_NOT_SUPPORTED;
    case DX_RET_UNSUPP_ALG_MODE:
    case DX_RET_UNSUPP_OPERATION:
        return CRYS_AES_ILLEGAL_OPERATION_MODE_ERROR;
    case DX_RET_INVARG:
    case DX_RET_INVARG_QID:
        return CRYS_AES_ILLEGAL_PARAMS_ERROR;
    case DX_RET_INVARG_KEY_SIZE:
        return CRYS_AES_WRAP_KEY_LENGTH_ERROR;
    case DX_RET_INVARG_CTX_IDX:
        return CRYS_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    case DX_RET_INVARG_CTX:
        return CRYS_AES_USER_CONTEXT_CORRUPTED_ERROR;
    case DX_RET_INVARG_BAD_ADDR:
        return CRYS_AES_WRAP_ILLEGAL_WRAP_DATA_PTR_ERROR;
    case DX_RET_NOMEM:
        return CRYS_OUT_OF_RESOURCE_ERROR;
    case DX_RET_INVARG_INCONSIST_DMA_TYPE:
        return CRYS_ILLEGAL_RESOURCE_VAL_ERROR;
    case DX_RET_PERM:
    case DX_RET_NOEXEC:
    case DX_RET_BUSY:
    case DX_RET_OSFAULT:
    default:
        return CRYS_FATAL_ERROR;
    }
}

static CRYSError_t handleDataPointers(uint8_t *Data_ptr, uint32_t DataLen, uint8_t *cache_buffer, uint8_t needToCopy,
                                      uint8_t **valid_ptr)
{
    DmaBuffer_s *DmaBuffPtr = NULL;
    int rc;
    CRYSError_t crysErr = CRYS_OK;

    *valid_ptr = NULL; /* Default in case of error */

    if (!IS_SMART_PTR(Data_ptr)) {
        *valid_ptr = Data_ptr;
    } else { /* Smart ptr. */
        DmaBuffPtr = PTR_TO_DMA_BUFFER(Data_ptr);
        if (DmaBuffPtr->dmaBufType != DMA_BUF_SEP) {
            if (needToCopy)
                /* in case fo wrap inplace operation from Host DataLen may be less then length
                  of MLLI buffers in DMA object */
                crysErr = CRYS_Bypass(Data_ptr, DataLen, cache_buffer);
            if (crysErr == CRYS_OK)
                *valid_ptr = cache_buffer;
        } else {
            /* SEP buffer */
            rc = validateDmaBuffer(DmaBuffPtr, DataLen);
            if (rc == -1) {
                crysErr = CRYS_AES_WRAP_DATA_LENGTH_ERROR;
            } else if (rc == -2) {
                crysErr = CRYS_AES_WRAP_ILLEGAL_DATA_PTR_ERROR;
            } else {
                *valid_ptr = (uint8_t *)(DxVirtAddr_t)DmaBuffPtr->pData;
            }
        }
    }
    return crysErr;
}

/*                CRYS_AES_Wrap function                                 *
 * *********************************************************************** */
/*
   @brief  The CRYS_AES_Wrap function implements the following algorithm
           (rfc3394, Sept. 2002):

    Inputs:  Plaintext DataIn, n 64-bit values {P1, P2, ..., Pn},
            KeyData, K (the KEK).
   Outputs: Ciphertext, WrapDataOut (n+1) 64-bit values {C0, C1, ..., Cn}.

   Steps:
           1. Initialize variables.
               Set A = IV, an initial value (see 2.2.3)
               For i = 1 to n
                   R[i] = P[i]
           2. Calculate intermediate values.
               For j = 0 to 5
                   For i=1 to n
                       B = AES(K, A | R[i])
                       A = MSB(64, B) ^ t ,
                            where: t = (n*j)+i  and  "^"  is the  XOR  operation.
                       R[i] = LSB(64, B)
           3. Output the result C.
               Set C[0] = A
               For i = 1 to n
                   C[i] = R[i].

   @param[in]  DataIn_ptr - A pointer to plain text data to be wrapped
                            NOTE: Overlapping between the data input and data output buffer
                                  is not allowed, except the inplace case that is legal .
   @param[in]  DataInLen  - Length of data in bytes. DataLen must be multiple of
                            8 bytes and  must be in range [8,512].
   @param[in]  KeyData    - KeyData Pointer to 16/24/32 byte buffer in SeP SRAM or  DX_KeyObjHandle_t
   @param[in]  KeySize    - Enumerator variable, defines length of key.
   @param[out] WrapDataOut_ptr -    A pointer to buffer for output of wrapped data.
   @param[in/out] WrapDataLen_ptr - A pointer to a buffer for input of size of
                                    user passed buffer and for output actual
                                    size of unwrapped data in bytes. Buffer size must
                                    be not less than DataLen+CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES.

   @return CRYSError_t - CRYS_OK, or error message
                         CRYS_AES_WRAP_ILLEGAL_DATA_PTR_ERROR
                         CRYS_AES_WRAP_DATA_LENGTH_ERROR
                         CRYS_AES_WRAP_ILLEGAL_KEY_PTR_ERROR
                         CRYS_AES_WRAP_KEY_LENGTH_ERROR
                         CRYS_AES_WRAP_ILLEGAL_WRAP_DATA_PTR_ERROR
                         CRYS_AES_WRAP_ILLEGAL_WRAP_DATA_LEN_PTR_ERROR
                         CRYS_AES_WRAP_ILLEGAL_WRAP_DATA_LENGTH_ERROR
                         CRYS_AES_WRAP_DATA_OUT_DATA_IN_OVERLAP_ERROR
                         CRYS_AES_WRAP_IS_SECRET_KEY_FLAG_ILLEGAL_ERROR

    NOTE:  On error exiting from function the output buffer may be zeroed by the function.

*/
CIMPORT_C CRYSError_t CRYS_AES_Wrap(uint8_t *DataIn_ptr,        /* in */
                                    uint32_t DataInLen,         /* in */
                                    CRYS_AES_Key_t KeyData,     /* in */
                                    CRYS_AES_KeySize_t KeySize, /* in */
                                    uint8_t *WrapDataOut_ptr,   /* out */
                                    uint32_t *WrapDataLen_ptr /* in/out */)
{
    /* ****************  LOCAL DECLARATIONS  ****************************** */

    /* The return error identifiers */
    CRYSError_t Error = CRYS_OK;

    int32_t NumOfBlocks;
    int32_t i, j;
    uint32_t DataSize = 2 * CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES;
    uint32_t T, baseT;

    /* Aes key size bytes */
    uint32_t KeySizeBytes = 0;

    uint32_t ctxBuff[CRYS_AES_WRAP_BUFF_OF_WORDS] = { 0x0 };
    struct sep_ctx_cipher *pAesContext            = (struct sep_ctx_cipher *)DX_InitUserCtxLocation(
        ctxBuff, CRYS_AES_WRAP_BUFF_OF_WORDS_IN_BYTES, sizeof(struct sep_ctx_cipher));
    uint8_t *tempIn, *tempOut;

    uint8_t *keyAddr;
    enum sep_crypto_key_type cryptoKeyType;
    KeyPtrType_t keyPtrType;
    keyBuffer_t keyBuff;

    uint32_t A_ptr[2 * CRYS_AES_WRAP_BLOCK_SIZE_IN_WORDS] = { 0 };
    uint32_t B_ptr[2 * CRYS_AES_WRAP_BLOCK_SIZE_IN_WORDS] = { 0 };
    int qid                                               = CURR_QUEUE_ID();
    int symRc                                             = DX_RET_OK;

    /* ---------------------------------------------------------------------- */
    /*            Check input parameters                                    */
    /* ---------------------------------------------------------------------- */

    /* Check input pointers */
    if (DataIn_ptr == DX_NULL)
        return CRYS_AES_WRAP_ILLEGAL_DATA_PTR_ERROR;

    if (WrapDataOut_ptr == DX_NULL)
        return CRYS_AES_WRAP_ILLEGAL_WRAP_DATA_PTR_ERROR;

    if (WrapDataLen_ptr == DX_NULL)
        return CRYS_AES_WRAP_ILLEGAL_WRAP_DATA_LEN_PTR_ERROR;

    if (KeyData == DX_NULL)
        return CRYS_AES_WRAP_ILLEGAL_KEY_PTR_ERROR;

    if (pAesContext == DX_NULL) {
        return CRYS_AES_WRAP_ILLEGAL_DATA_PTR_ERROR;
    }

    /* Check length of input parameters */
    if (DataInLen % CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES)
        return CRYS_AES_WRAP_DATA_LENGTH_ERROR;

    if (DataInLen < CRYS_AES_WRAP_DATA_MIN_SIZE_IN_BYTES)
        return CRYS_AES_WRAP_DATA_LENGTH_ERROR;

    if (DataInLen > CRYS_AES_WRAP_DATA_MAX_SIZE_IN_BYTES)
        return CRYS_AES_WRAP_DATA_LENGTH_ERROR;

    /* Check wrapped data buffer length */
    if (*WrapDataLen_ptr < DataInLen + CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES)
        return CRYS_AES_WRAP_ILLEGAL_WRAP_DATA_LENGTH_ERROR;

    if (getKeyDataFromKeyObj((uint8_t *)KeyData, &keyAddr, &cryptoKeyType, &keyPtrType, DX_AES_WRAP_API) != CRYS_OK)
        return CRYS_AES_WRAP_ILLEGAL_KEY_PTR_ERROR;

    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, DataIn_ptr, DataInLen) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ, KeyData, KeySize) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, WrapDataOut_ptr, *WrapDataLen_ptr) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, WrapDataLen_ptr, sizeof(uint32_t))) {
        return CRYS_AES_ILLEGAL_PARAMS_ERROR;
    }

    Error = handleDataPointers(DataIn_ptr, DataInLen, GlobalInCacheBuffer[qid], 1, &tempIn);
    if (Error != CRYS_OK)
        return Error;

    Error = handleDataPointers(WrapDataOut_ptr, *WrapDataLen_ptr, GlobalOutCacheBuffer[qid], 0, &tempOut);
    if (Error != CRYS_OK)
        return Error;

    /* Check that there is no overlapping between the data input and data output buffer
     except the inplace case that is legal */
    if ((tempIn > tempOut) && (tempIn < tempOut + DataInLen + CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES))
        return CRYS_AES_WRAP_DATA_OUT_DATA_IN_OVERLAP_ERROR;

    if ((tempIn < tempOut) && (tempIn > tempOut - DataInLen))
        return CRYS_AES_WRAP_DATA_OUT_DATA_IN_OVERLAP_ERROR;

    /* -------------------------------------------------------------------- */
    /* ............... local initializations .............................. */
    /* -------------------------------------------------------------------- */

    /* in case isSecretKey == DX_FALSE set KeySizeBytes value and copy AES key into Context */

    Error = buildKeyInt(pAesContext, &KeySize, keyBuff, &keyAddr, DX_AES_WRAP_API, cryptoKeyType, &KeySizeBytes);

    if (Error != CRYS_OK) {
        return CRYS_AES_WRAP_ILLEGAL_KEY_PTR_ERROR;
    }

    pAesContext->key_size        = KeySizeBytes;
    pAesContext->alg             = SEP_CRYPTO_ALG_AES;
    pAesContext->mode            = SEP_CIPHER_ECB;
    pAesContext->direction       = SEP_CRYPTO_DIRECTION_ENCRYPT;
    pAesContext->crypto_key_type = SEP_USER_KEY;

    symRc = SymDriverAdaptorInit((struct sep_ctx_generic *)pAesContext);
    if (symRc != DX_RET_OK) {
        return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysAesWrapErr);
    }

    /* Initialize a number of 64-bit blocks */
    NumOfBlocks = (int32_t)(DataInLen / CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

    /* ********************   FUNCTION LOGIC  ****************************** */

    /* Set IV into A */
    DX_PAL_MemSet(A_ptr, CRYS_AES_WRAP_RFC3394_IV, CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

    /* Copy remining input data into output buffer for next operations.
       "memmove" has to be used because of data overlaping in case of inplace operattion.
       DX_PAL_MemCopy uses memmove in RTOS implementation */
    DX_PAL_MemMove(tempOut + CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES, tempIn, DataInLen);

    /* Calculate intermediate values */
    baseT = 0x0;

    for (j = 0; j <= CRYS_AES_WRAP_STEPS - 1; j++) {
        for (i = 1; i <= NumOfBlocks; i++) {
            DX_PAL_MemCopy(A_ptr + CRYS_AES_WRAP_BLOCK_SIZE_IN_WORDS, &tempOut[i * CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES],
                           CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

            symRc = SymDriverAdaptorProcess((struct sep_ctx_generic *)pAesContext, A_ptr, B_ptr, DataSize);
            if (symRc != DX_RET_OK) {
                return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysAesWrapErr);
            }
            /* A_ptr = MSB(64, B)^T, where: T = (n*j)+i */

            /* Calculate T and reverse its endian for XORing */

#ifdef BIG__ENDIAN
            T = (uint32_t)(baseT + i);
#else
            /* Calculate T and reverse its endian for XORing */
            T = CRYS_COMMON_REVERSE32((uint32_t)(baseT + i));
#endif

            A_ptr[0] = B_ptr[0];
            A_ptr[1] = B_ptr[1] ^ T;

            /* WrapData[i] = R[i] = LSB(64, B); */
            DX_PAL_MemCopy(&tempOut[i * CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES], &B_ptr[CRYS_AES_WRAP_BLOCK_SIZE_IN_WORDS],
                           CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

        } /* END for(i) */
        baseT = baseT + NumOfBlocks;
    } /* END for(j) */

    /* Copy A into 0-block of the wrapped data */
    DX_PAL_MemCopy(tempOut, A_ptr, CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

    /* Set the actual length of the output data in bytes */
    *WrapDataLen_ptr = (uint32_t)((NumOfBlocks + 1) * CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

    /* If worked on temp cache buffers, copy back to host mem */
    if (GlobalOutCacheBuffer[qid] == tempOut) {
        Error = CRYS_Bypass(tempOut, *WrapDataLen_ptr, WrapDataOut_ptr);
    }

    return Error;

} /* End of CRYS_AES_Wrap */

/* *************************************************************************
 *                CRYS_AES_Unwrap function                                *
 * *********************************************************************** */
/*
   @brief  The CRYS_AES_Unwrap function performs inverse AES_Wrap transformation
           and implements the following algorithm (rfc3394, Sept. 2002):

   Inputs:  Ciphertext, WrapDataIn (n+1) 64-bit values {C0, C1, ..., Cn}, and
            K  - key (the KEK).
   Outputs: Plaintext, DataOut n 64-bit values {P1, P2, ..., Pn}.

   Steps:
           1. Initialize variables:
           Set A = C[0]
               For i = 1 to n
                   R[i] = C[i]
           2. Compute intermediate values:
               For j = 5 to 0
                   For i = n to 1
                       B = AES-1(K, (A ^ t) | R[i]) ,
                            where:  t = n*j+i  and  "^" is the  XOR  operation.
                       A = MSB(64, B)
                       R[i] = LSB(64, B)
           3. Output results:
           If A is an appropriate initial value (see 2.2.3), then
               For i = 1 to n
                   P[i] = R[i]
           Else
               Return an error.

   @param[in]  WrapDataIn_ptr - A pointer to wrapped data to be unwrapped
                                NOTE: Overlapping between the data input and data output buffer
                                      is not allowed, except the inplace case that is legal .
   @param[in]  WrapDataInLen  - Length of wrapped data in bytes. DataLen must be multiple of
                                8 bytes and  must be in range [16, (512+8)].
   @param[in]  KeyData        - KeyData Pointer to a 16/24/32 byte buffer in SeP SRAM or  DX_KeyObjHandle_t
   @param[in]  KeySize        - Enumerator variable, defines length of key.
   @param[out] DataOut_ptr    - A pointer to buffer for output of unwrapped data.
   @param[in/out]  DataOutLen_ptr - A pointer to a buffer for input of size of user passed
                              buffer and for output of actual size of unwrapped data in bytes.
                              DataOutLen must be multiple of 8 bytes and must be not less
                              than WrapDataInLen - CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES.

   @return CRYSError_t - CRYS_OK, or error message
                         CRYS_AES_UNWRAP_WRAP_DATA_LENGTH_ERROR
                         CRYS_AES_UNWRAP_ILLEGAL_KEY_PTR_ERROR
                         CRYS_AES_UNWRAP_KEY_LEN_ERROR
                         CRYS_AES_UNWRAP_ILLEGAL_DATA_PTR_ERROR
                         CRYS_AES_UNWRAP_ILLEGAL_DATA_LEN_PTR_ERROR
                         CRYS_AES_UNWRAP_ILLEGAL_DATA_LENGTH_ERROR
                         CRYS_AES_UNWRAP_FUNCTION_FAILED_ERROR
                         CRYS_AES_UNWRAP_DATA_OUT_DATA_IN_OVERLAP_ERROR
                         CRYS_AES_UNWRAP_IS_SECRET_KEY_FLAG_ILLEGAL_ERROR

    NOTE:  On error exiting from function the output buffer may be zeroed by the function.
*/

CIMPORT_C CRYSError_t CRYS_AES_Unwrap(uint8_t *WrapDataIn_ptr,    /* in */
                                      uint32_t WrapDataInLen,     /* in */
                                      CRYS_AES_Key_t KeyData,     /* in */
                                      CRYS_AES_KeySize_t KeySize, /* in */
                                      uint8_t *DataOut_ptr,       /* out */
                                      uint32_t *DataOutLen_ptr /* in/out */)

{
    /* ****************  LOCAL DECLARATIONS  ****************************** */

    CRYSError_t Error = CRYS_OK;

    int32_t NumOfBlocks;
    int32_t i, j;
    uint32_t DataSize = 2 * CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES;
    uint32_t T, baseT;

    /* Aes key size bytes */
    uint32_t KeySizeBytes = 0;

    uint32_t ctxBuff[CRYS_AES_WRAP_BUFF_OF_WORDS] = { 0x0 };
    struct sep_ctx_cipher *pAesContext            = (struct sep_ctx_cipher *)DX_InitUserCtxLocation(
        ctxBuff, CRYS_AES_WRAP_BUFF_OF_WORDS_IN_BYTES, sizeof(struct sep_ctx_cipher));
    uint8_t *tempIn, *tempOut;

    uint8_t *keyAddr;
    enum sep_crypto_key_type cryptoKeyType;
    KeyPtrType_t keyPtrType;
    keyBuffer_t keyBuff;

    uint32_t A_ptr[2 * CRYS_AES_WRAP_BLOCK_SIZE_IN_WORDS] = { 0 };
    uint32_t B_ptr[2 * CRYS_AES_WRAP_BLOCK_SIZE_IN_WORDS] = { 0 };

    int qid   = CURR_QUEUE_ID();
    int symRc = DX_RET_OK;

    /* Check input pointers */
    if (WrapDataIn_ptr == DX_NULL)
        return CRYS_AES_UNWRAP_ILLEGAL_WRAP_DATA_PTR_ERROR;

    if (DataOut_ptr == DX_NULL)
        return CRYS_AES_UNWRAP_ILLEGAL_DATA_PTR_ERROR;

    if (DataOutLen_ptr == DX_NULL)
        return CRYS_AES_UNWRAP_ILLEGAL_DATA_LEN_PTR_ERROR;

    if (KeyData == DX_NULL) {
        return CRYS_AES_WRAP_ILLEGAL_KEY_PTR_ERROR;
    }

    if (pAesContext == DX_NULL) {
        return CRYS_AES_UNWRAP_ILLEGAL_DATA_PTR_ERROR;
    }

    /* Check length of input parameters */
    if (WrapDataInLen % CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES)
        return CRYS_AES_UNWRAP_WRAP_DATA_LENGTH_ERROR;

    if (WrapDataInLen < (CRYS_AES_WRAP_DATA_MIN_SIZE_IN_BYTES + CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES))
        return CRYS_AES_UNWRAP_WRAP_DATA_LENGTH_ERROR;

    if (WrapDataInLen > (CRYS_AES_WRAP_DATA_MAX_SIZE_IN_BYTES + CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES))
        return CRYS_AES_UNWRAP_WRAP_DATA_LENGTH_ERROR;

    /* Check unwrapped data buffer length */
    if (*DataOutLen_ptr < WrapDataInLen - CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES)
        return CRYS_AES_UNWRAP_ILLEGAL_DATA_LENGTH_ERROR;

    if (getKeyDataFromKeyObj((uint8_t *)KeyData, &keyAddr, &cryptoKeyType, &keyPtrType, DX_AES_WRAP_API) != CRYS_OK) {
        return CRYS_AES_WRAP_ILLEGAL_KEY_PTR_ERROR;
    }

    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, WrapDataIn_ptr, WrapDataInLen) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ, KeyData, KeySize) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, DataOut_ptr, *DataOutLen_ptr) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, DataOutLen_ptr, sizeof(uint32_t))) {
        return CRYS_AES_ILLEGAL_PARAMS_ERROR;
    }

    Error = handleDataPointers(WrapDataIn_ptr, WrapDataInLen, GlobalInCacheBuffer[qid], 1, &tempIn);
    if (Error != CRYS_OK)
        return Error;

    Error = handleDataPointers(DataOut_ptr, *DataOutLen_ptr, GlobalOutCacheBuffer[qid], 0, &tempOut);
    if (Error != CRYS_OK)
        return Error;

    /* Check that there is no overlapping between the data input and data output buffer
    except the inplace case that is legal */
    if (tempIn > tempOut && tempIn < tempOut + WrapDataInLen - CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES)
        return CRYS_AES_UNWRAP_DATA_OUT_DATA_IN_OVERLAP_ERROR;

    if (tempIn < tempOut && tempIn > tempOut - WrapDataInLen)
        return CRYS_AES_UNWRAP_DATA_OUT_DATA_IN_OVERLAP_ERROR;

    /* in case isSecretKey == DX_FALSE set KeySizeBytes value and copy AES key into Context */
    /* we use pAesContext as temp memmory for buildAppletkey() internal crypto operations,
      applet key is  copied directly to aes key in context */
    Error = buildKeyInt(pAesContext, &KeySize, keyBuff, &keyAddr, DX_AES_WRAP_API, cryptoKeyType, &KeySizeBytes);
    if (Error != CRYS_OK)
        return CRYS_AES_WRAP_ILLEGAL_KEY_PTR_ERROR;

    pAesContext->key_size        = KeySizeBytes;
    pAesContext->alg             = SEP_CRYPTO_ALG_AES;
    pAesContext->mode            = SEP_CIPHER_ECB;
    pAesContext->direction       = SEP_CRYPTO_DIRECTION_DECRYPT;
    pAesContext->crypto_key_type = SEP_USER_KEY;

    symRc = SymDriverAdaptorInit((struct sep_ctx_generic *)pAesContext);
    if (symRc != DX_RET_OK) {
        return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysAesWrapErr);
    }

    /* calculate n - number of 64-bit blocks of unwrapped data */
    NumOfBlocks = (int32_t)(WrapDataInLen / CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES - 1);

    /* ********************   FUNCTION LOGIC  ****************************** */

    /* Copy C[0] into A */
    DX_PAL_MemCopy((void *)A_ptr, tempIn, CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

    /* Copy remining input data into output buffer for next operations.
       "memmove" has to be used becouse of data overlaping in case of inplace operattion
       DX_PAL_MemCopy uses memmove in RTOS implementation */
    DX_PAL_MemMove(tempOut /* + CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES */, tempIn + CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES,
                   WrapDataInLen - CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

    /* Calculate intermediate values */
    baseT = (NumOfBlocks << 2) + NumOfBlocks; /* NumOfBlocks * 5 */

    for (j = CRYS_AES_WRAP_STEPS - 1; j >= 0; j--) {
        for (i = NumOfBlocks; i >= 1; i--) {
            /* Calculate T and reverse its endian for XORing */
#ifdef BIG__ENDIAN
            T = (uint32_t)(baseT + i);
#else
            /* Calculate T and reverse its endian for XORing */
            T = CRYS_COMMON_REVERSE32((uint32_t)(baseT + i));
#endif

            /* Calculate (A^T)|R[i]   */
            A_ptr[1] = A_ptr[1] ^ T;
            DX_PAL_MemCopy(&A_ptr[2], tempOut + (i - 1) * CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES,
                           CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

            symRc = SymDriverAdaptorProcess((struct sep_ctx_generic *)pAesContext, A_ptr, B_ptr, DataSize);
            if (symRc != DX_RET_OK) {
                return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysAesWrapErr);
            }

            /* A = MSB(64, B)   */
            A_ptr[0] = B_ptr[0];
            A_ptr[1] = B_ptr[1];

            /* WrapData[i] = R[i] = LSB(64, B); */
            DX_PAL_MemCopy(&tempOut[(i - 1) * CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES],
                           (void *)(&B_ptr[CRYS_AES_WRAP_BLOCK_SIZE_IN_WORDS]), CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

        } /* for(i) */
        baseT = baseT - NumOfBlocks;
    } /* for(j) */

    /* Check that A = AES_WRAP_IV */
    for (i = 0; i < CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES; i++) {
        if (((uint8_t *)A_ptr)[i] != CRYS_AES_WRAP_RFC3394_IV) {
            return CRYS_AES_UNWRAP_FUNCTION_FAILED_ERROR;
        }
    }

    /* Set the actual length of the output data in bytes */
    *DataOutLen_ptr = (uint32_t)(NumOfBlocks * CRYS_AES_WRAP_BLOCK_SIZE_IN_BYTES);

    /* If worked on temp cache buffers, copy back to host mem */
    if (GlobalOutCacheBuffer[qid] == tempOut) {
        Error = CRYS_Bypass(tempOut, *DataOutLen_ptr, DataOut_ptr);
    }

    return Error;

} /* End of CRYS_AES_Uwnrap */
