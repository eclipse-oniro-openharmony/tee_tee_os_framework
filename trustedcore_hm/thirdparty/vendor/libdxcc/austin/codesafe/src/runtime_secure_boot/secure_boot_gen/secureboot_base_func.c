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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_SECURE_BOOT

/* ************ Include Files ************** */
#include "secureboot_error.h"
#include "secureboot_defs.h"
#include "crypto_driver_defs.h"
#include "crypto_driver.h"
#include "util.h"
#include "bootimagesverifier_error.h"
#include "rsa.h"
#include "nvm.h"
#include "crys_hash.h"
#include "dx_pal_mem.h"
#include "crys_rsa_types.h"
#include "crys_rsa_build.h"
#include "crys_rsa_schemes.h"
#include "util.h"
#include "dx_pal_mutex.h"
#include "dx_pal_abort.h"
#include "dx_pal_log.h"
#include "sbrt_management_api.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Internal Functions **************************** */

/* *********************** Public Functions **************************** */
extern DX_PAL_MUTEX dxSymCryptoMutex;

DxError_t DX_SB_CalcPublicKeyHASH(uint32_t *NAndRevNp_ptr, HASH_Result_t hashResult)
{
    /* error variable */
    DxError_t error = DX_SUCCESS;
    CRYS_HASH_Result_t CrysHashResult;

    /* ------------------
        CODE
    ------------------- */

    error = CRYS_HASH(CRYS_HASH_SHA256_mode, (uint8_t *)NAndRevNp_ptr,
                      (SB_RSA_MOD_SIZE_IN_WORDS + SB_RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_WORDS) * sizeof(uint32_t),
                      CrysHashResult);

    DX_PAL_MemCopy(hashResult, CrysHashResult, sizeof(HASH_Result_t));

    return error;
}

DxError_t DX_SB_CalcPublicKeyHASHAndCompare(uint32_t *NAndRevNp_ptr, HASH_Result_t NHASH_ptr, uint32_t HashSize)
{
    /* error variable */
    DxError_t error = DX_SUCCESS;

    /* HASH result of the E||N */
    HASH_Result_t LocalHashResult;

    /* ------------------
        CODE
    ------------------- */

    /* calculate the HASH value of N (big endian)|| Np (reversed - little endian) */
    error = DX_SB_CalcPublicKeyHASH(NAndRevNp_ptr, LocalHashResult);
    if (error != DX_SUCCESS)
        return error;

    /* compare the HASH results */
    error = DX_PAL_MemCmp((uint8_t *)LocalHashResult, (uint8_t *)NHASH_ptr, HashSize);
    if (error != DX_SUCCESS) {
        DX_PAL_LOG_ERR("PUB KEY HASH VALIDATION FAILURE\n");
        return DX_BOOT_IMG_VERIFIER_PUB_KEY_HASH_VALIDATION_FAILURE;
    }

    return DX_SUCCESS;
} /* End of DX_SB_CalcPublicKeyHASHAndCompare */

DxError_t DX_SB_VerifySignature(uint32_t *pData, DxSbNParams_t *pNParams, DxSbSignature_t *pSignature,
                                uint32_t sizeOfData, DxSbRsaAlg_t RSAAlg, uint32_t *workspace_ptr,
                                uint32_t workspaceSize)
{
    /* error variable */
    DxError_t error = DX_SUCCESS;

    CRYS_RSAUserPubKey_t *UserPubKey_ptr;
    CRYS_RSAPubUserContext_t *UserContext_ptr;
    CRYSRSAPubKey_t *rsaPubKey_ptr;
    uint8_t pub_exp[] = { 0x01, 0x00, 0x01 };

    /* reversed N public key */
    uint32_t RevN[SB_RSA_MOD_SIZE_IN_WORDS];
    uint32_t RevNp[SB_RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_WORDS];
    /* reversed signature */
    uint32_t RevSig[SB_RSA_MOD_SIZE_IN_WORDS];

    /* ------------------
        CODE
    ------------------- */

    /* Currently only RSA_PSS_2048 is supported */
    if (RSAAlg != RSA_PSS_2048) {
        DX_PAL_LOG_DEBUG("UNSUPPORTED RSA ALGORITHM\n");
        return DX_BOOT_IMG_VERIFIER_UNSUPPORTED_RSA_ALGORITHM;
    }

    /* Reverse the signature */
    UTIL_ReverseMemCopy((uint8_t *)RevSig, (uint8_t *)pSignature->sig, sizeof(uint32_t) * SB_RSA_MOD_SIZE_IN_WORDS);
    /* Reverse the N and Np to be little endian arrays for the PKA usage */
    UTIL_ReverseMemCopy((uint8_t *)RevN, (uint8_t *)pNParams->N, RSA_MOD_SIZE_IN_BYTES);
    UTIL_ReverseMemCopy((uint8_t *)RevNp, (uint8_t *)pNParams->Np,
                        sizeof(uint32_t) * SB_RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_WORDS);

    /* Check workspace size */
    if ((sizeof(CRYS_RSAUserPubKey_t) + sizeof(CRYS_RSAPubUserContext_t)) > workspaceSize)
        return DX_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;

    /* Init workspace buffer */
    DX_PAL_MemSet(workspace_ptr, 0, sizeof(CRYS_RSAUserPubKey_t) + sizeof(CRYS_RSAPubUserContext_t));

    /* Verify the RSA signature of the certificate */
    /* --------------------------------------------- */
    /* Use workspace buffer for CRYS public key buffer */
    UserPubKey_ptr = (CRYS_RSAUserPubKey_t *)workspace_ptr;

    /* Build public key */
    rsaPubKey_ptr             = (CRYSRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;
    UserPubKey_ptr->valid_tag = RSA_PUB_KEY_VALIDATION_TAG;
    DX_PAL_MemCopy(rsaPubKey_ptr->e, pub_exp, sizeof(pub_exp));
    rsaPubKey_ptr->eSizeInBits = RSA_EXP_SIZE_IN_BYTES * 8;
    DX_PAL_MemCopy(rsaPubKey_ptr->n, RevN, SB_RSA_MOD_SIZE_IN_WORDS * sizeof(uint32_t));
    rsaPubKey_ptr->nSizeInBits = RSA_MOD_SIZE_IN_BITS;
    DX_PAL_MemCopy(rsaPubKey_ptr->crysRSAIntBuff, RevNp,
                   SB_RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_WORDS * sizeof(uint32_t));

    /* Use workspace buffer for CRYS public content buffer */
    UserContext_ptr = (CRYS_RSAPubUserContext_t *)(workspace_ptr + sizeof(CRYS_RSAUserPubKey_t) / sizeof(uint32_t));

    /* Verify the signature */
    error = CRYS_RSA_PSS_Verify(UserContext_ptr, UserPubKey_ptr, CRYS_RSA_HASH_SHA256_mode, CRYS_PKCS1_MGF1,
                                (uint16_t)RSA_PSS_SALT_LENGTH, (uint8_t *)pData, sizeOfData, (uint8_t *)RevSig);

    if (error != DX_SUCCESS) {
        DX_PAL_LOG_DEBUG("CRYS_RSA_Build_PubKey faild\n");
        return DX_BOOT_IMG_VERIFIER_RSA_SIG_VERIFICATION_FAILED;
    }

    return DX_SUCCESS;

} /* End of DX_SB_VerifySignature */

DxError_t DX_SB_CalcHASHOnSWRecDecryptAndCompare(DxSbFlashReadFunc preHashflashRead_func, void *preHashUserContext,
                                                 uint32_t hashOutputSize, uint32_t *recHashData_ptr,
                                                 uint32_t *recAddInfo_ptr, AES_Key_t *aesKey,
                                                 uint8_t isSwComponentEncrypted, DxSbNonce_t nonce,
                                                 uint32_t *workspace_ptr, uint32_t workspaceSize)
{
    /* error variable */
    DxError_t error = DX_SUCCESS;
    /* SW component temp size */
    uint32_t sizeToReadInBytes = 0, currentSize = 0, sizeOfTotalSections = workspaceSize;

    /* a flag indicating if its last operation or not */
    uint8_t isLastBlock = DX_FALSE;

    /* HASH result buffer */
    HASH_Result_t HASHResult;

    /* AES IV buffer */
    AES_Iv_t AESIv;

    /* the address in the Flash to read from */
    uint64_t currStoreAddress = 0, currLoadAddress = 0;

    /* temp buf pointers */
    uint32_t *workRam1 = DX_NULL, *workRam2 = DX_NULL;
    DxDmaAddr_t tempAddr = 0;

    /* flag indicating if to load to memory or use temporary memory */
    uint8_t isLoadMemory = DX_TRUE;

    /* set default crypto mode to hash only (wo encryption) */
    CryptoDriverMode_t cryptoDriverMode = CRYPTO_DRIVER_HASH_MODE;

    /* crypto operation mode for double buffer usage */
    DX_SB_CryptoCompletionMode_t isWaitForCryptoCompletion;

    /* length of record , first is the storage address 64 bits second is the len */
    uint32_t recLen = *(recAddInfo_ptr + sizeof(uint64_t) / sizeof(uint32_t));

    /* ------------------
        CODE
    ------------------- */

    /* In order to improve performance the Loading from Flash will be done simultaneously
       to calculating the HASH */
    /* Initialize parameters */
    /* ----------------------- */
    /* validate the s/w component size - we do not support size zero */
    if (recLen == 0) {
        DX_PAL_LOG_DEBUG("SW comp size is NULL\n");
        return DX_BOOT_IMG_VERIFIER_SW_COMP_SIZE_IS_NULL;
    }
    /* Get the memory load address */
    DX_PAL_MemCopy((uint8_t *)&currLoadAddress, (uint8_t *)(recHashData_ptr + hashOutputSize / sizeof(uint32_t)),
                   sizeof(uint64_t));

    /* In case the s/w component should not be loaded, the function will use the temporary memory given
       Else, the data will be loded directly to final load address as given in the certificate */
    if (currLoadAddress == DX_SW_COMP_NO_MEM_LOAD_INDICATION) {
        isLoadMemory = DX_FALSE;

        /* The workspace minimum size must be at least DX_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES,
           if its not the function will return error (if temp memory should be used) */
        if (workspaceSize < DX_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES) {
            DX_PAL_LOG_DEBUG("workspace size too small\n");
            return DX_BOOT_IMG_VERIFIER_WORKSPACE_SIZE_TOO_SMALL;
        }

        /* Divide the workspace into 2 buffers, in order to allow reading and calculating HASH
         simultaneously , each buffer size is DX_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES/2 */
        workRam1 = workspace_ptr; /* Size of this section is DX_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES/2 */
        workRam2 = workspace_ptr + (DX_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES / 2) / sizeof(uint32_t);

        /* Starting with the first buffer */
        tempAddr = CONVERT_TO_ADDR(workRam1);

        /* Starting first half with no_wait to interrupt */
        isWaitForCryptoCompletion = DX_SB_CRYPTO_COMPLETION_NO_WAIT_ASK_ACK;
    } else { /* Point to the current memory address */
        tempAddr = currLoadAddress;

        /* Always work with no_wait to interrupts */
        isWaitForCryptoCompletion = DX_SB_CRYPTO_COMPLETION_NO_WAIT;
    }

    sizeOfTotalSections = DX_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES;

    /* Set the storage address */
    DX_PAL_MemCopy((uint8_t *)&currStoreAddress, (uint8_t *)recAddInfo_ptr, sizeof(uint64_t));

    /* Set the s/w component size */
    currentSize = recLen * sizeof(uint32_t);

    /* Fixed size to read */
    sizeToReadInBytes = sizeOfTotalSections / 2;

    /* Initialize the crypto process  */
    /* -------------------------------- */
    if (isSwComponentEncrypted) {
        /* AES IV compose of : nonce[0], nonce[1], Load Addres, 0 */
        DX_PAL_MemSet((uint8_t *)AESIv, 0, AES_IV_COUNTER_SIZE_IN_BYTES);
        /* copy nonce */
        DX_PAL_MemCopy((uint8_t *)&AESIv[0], (uint8_t *)nonce, DX_SB_MAX_SIZE_NONCE_BYTES);
/* copy address */
#ifdef BIG__ENDIAN
        DX_PAL_MemCopy((uint8_t *)&AESIv[2], (uint8_t *)&currLoadAddress, sizeof(uint64_t));
#else
        UTIL_ReverseMemCopy((uint8_t *)&AESIv[2], (uint8_t *)&currLoadAddress, sizeof(uint64_t));
#endif

        cryptoDriverMode = CRYPTO_DRIVER_HASH_AES_CTR_MODE;
    }
    /* Lock mutex for sym operation */
    error = DX_PAL_MutexLock(&dxSymCryptoMutex, DX_INFINITE);
    if (error != DX_SUCCESS) {
        DX_PAL_Abort("Fail to acquire mutex\n");
    }

    /* initialize the AES and HASH */
    error = SB_CryptoInit(aesKey, &AESIv, cryptoDriverMode);
    if (error != DX_SUCCESS)
        goto End;

    /* Read the SW component from the flash in blocks and calculate HASH on it */
    /* ------------------------------------------------------------------------- */

    /* In a loop - read to buffer1 start the HASH on it and continue with buffer2 */
    while (currentSize > 0) {
        /* In case the remaining bytes to read are less than the size of the buffer */
        if (sizeToReadInBytes > currentSize || sizeToReadInBytes == currentSize) {
            /* Set the size to read to the size of the remaining bytes */
            sizeToReadInBytes = currentSize;

            /* Set the flag indicating this is the last operation */
            isLastBlock = DX_TRUE;
        }

        /* Read a block from the flash, according to the size of the buffer */
        error = preHashflashRead_func(currStoreAddress, (uint8_t *)(CONVERT_TO_ADDR(tempAddr)), sizeToReadInBytes,
                                      preHashUserContext);
        if (error != DX_SUCCESS)
            goto End;

        /* For each chunk that is read , perform hash operation and decryption (if needed).
           To improve performance, do not wait for completion operation */
        error = SB_CryptoUpdateBlock(CONVERT_TO_ADDR(tempAddr), CONVERT_TO_ADDR(tempAddr), sizeToReadInBytes,
                                     isLastBlock, cryptoDriverMode, isWaitForCryptoCompletion);
        if (error != DX_SUCCESS)
            goto End;

        /* Update the size to read, Flash address and buffer pointer */
        currentSize      = currentSize - sizeToReadInBytes;
        currStoreAddress = currStoreAddress + sizeToReadInBytes;

        /* Update completion */
        isWaitForCryptoCompletion = DX_SB_CRYPTO_COMPLETION_WAIT_UPON_START;

        if (isLoadMemory) { /* In case load to memory */
            /* advance the load address pointer */
            tempAddr = tempAddr + sizeToReadInBytes;

        } else {
            /* switch buffer pointers */
            if (tempAddr == CONVERT_TO_ADDR(workRam1))
                tempAddr = CONVERT_TO_ADDR(workRam2);
            else
                tempAddr = CONVERT_TO_ADDR(workRam1);
        }
    }

    /* Finish the HASH operation and get the results */
    /* ----------------------------------------------- */
    /* get the results */
    error = SB_CryptoFinish(HASHResult);
    if (error != DX_SUCCESS)
        goto End;

    /* Compare the HASH result with the SW component given HASH */
    /* ---------------------------------------------------------- */
    error = DX_PAL_MemCmp((uint8_t *)recHashData_ptr, (uint8_t *)HASHResult, hashOutputSize);
    if (error != DX_SUCCESS) {
        DX_PAL_LOG_DEBUG("SW comp failed verification\n");
        error = DX_BOOT_IMG_VERIFIER_SW_COMP_FAILED_VERIFICATION;
        goto End;
    }

End:

    if (DX_PAL_MutexUnlock(&dxSymCryptoMutex) != DX_SUCCESS) {
        DX_PAL_Abort("Fail to release mutex\n");
    }

    return error;

} /* End of DX_BIV_CalcHASHOnSWRecAndCompare */

DxError_t DX_SB_SetNvCounter(DxSbSwVersion_t *pCertNvCounter, uint32_t otpVersion)
{
    DxError_t error = DX_SUCCESS;

    if (pCertNvCounter == NULL)
        return DX_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;

    if (pCertNvCounter->swVersion > otpVersion) { // version is bigger - set the new version in the otp
        error = NVM_SetSwVersion(pCertNvCounter->id, pCertNvCounter->swVersion);
        if (error != DX_SUCCESS)
            return error;
    }

    return error;
}

DxError_t DX_SB_VerifyNvCounter(DxSbSwVersion_t *pCertNvCounter, uint8_t initFlag, DxSbSwVersionId_t prevNvCounterId,
                                uint32_t *otpVersion)
{
    DxError_t error = DX_SUCCESS;

    /* verify inputs */
    if (pCertNvCounter == NULL || otpVersion == NULL) {
        DX_PAL_LOG_ERR("invalid inputs\n");
        return DX_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    if (initFlag != 0 && prevNvCounterId != pCertNvCounter->id) {
        DX_PAL_LOG_ERR("previous counter id is different that current\n");
        return DX_BOOT_IMG_VERIFIER_CERT_VER_ID_ILLEGAL;
    }

    /* get sw version from OTP */
    error = DX_SBRT_GetSwVersion(pCertNvCounter->id, otpVersion);

    if (error != DX_SUCCESS)
        return error;
    if (pCertNvCounter->swVersion < *otpVersion) {
        DX_PAL_LOG_ERR("currSwVersion1 < minVersion\n");
        return DX_BOOT_IMG_VERIFIER_SW_VER_SMALLER_THAN_MIN_VER;
    } else if ((pCertNvCounter->id == DX_SW_VERSION_COUNTER1) &&
               (pCertNvCounter->swVersion > ((DX_SB_VERSION_COUNTER1_WIDTH * BITS_WITHIN_WORD) - 1))) {
        DX_PAL_LOG_ERR("currSwVersion1 > DX_SB_VERSION_COUNTER1_WIDTH\n");
        return DX_BOOT_IMG_VERIFIER_CERT_VER_ID_ILLEGAL;
    } else if ((pCertNvCounter->id == DX_SW_VERSION_COUNTER2) &&
               (pCertNvCounter->swVersion > ((DX_SB_VERSION_COUNTER2_WIDTH * BITS_WITHIN_WORD) - 1))) {
        DX_PAL_LOG_ERR("currSwVersion2 > DX_SB_VERSION_COUNTER2_WIDTH\n");
        return DX_BOOT_IMG_VERIFIER_CERT_VER_ID_ILLEGAL;
    }

    return DX_SUCCESS;
}
