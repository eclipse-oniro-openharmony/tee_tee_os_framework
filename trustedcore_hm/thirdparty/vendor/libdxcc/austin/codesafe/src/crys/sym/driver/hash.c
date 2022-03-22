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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CRYS_SYM_DRIVER

#include "dx_pal_types.h"
#include "dx_pal_mem.h"
#include "sym_crypto_driver.h"
#include "dx_error.h"
#include "cc_plat.h"
#include "mlli.h"
#include "hw_queue.h"
#include "sep_ctx.h"
#include "hash_defs.h"
#include "hash.h"
#include "completion.h"
#include "compiler.h"

DX_PAL_COMPILER_ASSERT(sizeof(struct sep_ctx_hash) == SEP_CTX_SIZE, "sep_ctx_hash is larger than 128 bytes!");
DX_PAL_COMPILER_ASSERT(sizeof(enum sep_hash_mode) == sizeof(uint32_t), "sep_hash_mode is not 32bit!");
DX_PAL_COMPILER_ASSERT(sizeof(enum sep_hash_hw_mode) == sizeof(uint32_t), "sep_hash_hw_mode is not 32bit!");
DX_PAL_COMPILER_ASSERT(sizeof(enum HashConfig1Padding) == sizeof(uint32_t), "HashConfig1Padding is not 32bit!");
DX_PAL_COMPILER_ASSERT(sizeof(enum HashCipherDoPadding) == sizeof(uint32_t), "HashCipherDoPadding is not 32bit!");

/* *****************************************************************************
 *                GLOBALS
 * *************************************************************************** */

const uint32_t gLarvalMd5Digest[] DX_SRAM_CONST    = { HASH_LARVAL_MD5 };
const uint32_t gLarvalSha1Digest[] DX_SRAM_CONST   = { HASH_LARVAL_SHA1 };
const uint32_t gLarvalSha224Digest[] DX_SRAM_CONST = { HASH_LARVAL_SHA224 };
const uint32_t gLarvalSha256Digest[] DX_SRAM_CONST = { HASH_LARVAL_SHA256 };
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
const uint32_t gLarvalSha384Digest[] DX_SRAM_CONST = { HASH_LARVAL_SHA384 };
const uint32_t gLarvalSha512Digest[] DX_SRAM_CONST = { HASH_LARVAL_SHA512 };
#endif
const uint32_t gOpadCurrentLength[] DX_SRAM_CONST = { OPAD_CURRENT_LENGTH };

/* Real expected size */
const uint32_t gHashDigestSize[SEP_HASH_MODE_NUM] = { SEP_SHA1_DIGEST_SIZE,   SEP_SHA256_DIGEST_SIZE,
                                                      SEP_SHA224_DIGEST_SIZE, SEP_SHA512_DIGEST_SIZE,
                                                      SEP_SHA384_DIGEST_SIZE, SEP_MD5_DIGEST_SIZE };
/* SHA224 is processed as SHA256! */
const uint32_t gHashHwDigestSize[SEP_HASH_MODE_NUM] = { SEP_SHA1_DIGEST_SIZE,   SEP_SHA256_DIGEST_SIZE,
                                                        SEP_SHA256_DIGEST_SIZE, SEP_SHA512_DIGEST_SIZE,
                                                        SEP_SHA512_DIGEST_SIZE, SEP_MD5_DIGEST_SIZE };
/* from the HW side, HASH512 and HASH384 are the same */
const uint32_t gHashHwMode[SEP_HASH_MODE_NUM] = { SEP_HASH_HW_SHA1,   SEP_HASH_HW_SHA256, SEP_HASH_HW_SHA256,
                                                  SEP_HASH_HW_SHA512, SEP_HASH_HW_SHA512, SEP_HASH_HW_MD5 };

/* !
 * Translate Hash mode to hardware specific Hash mode.
 *
 * \param mode Hash mode
 * \param hwMode [out] A pointer to the hash mode return value
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int GetHashHwMode(const enum sep_hash_mode mode, uint32_t *hwMode)
{
    if (mode >= SEP_HASH_MODE_NUM) {
        DX_PAL_LOG_ERR("Unsupported hash mode");
        *hwMode = SEP_HASH_NULL;
        return DX_RET_UNSUPP_ALG_MODE;
    }

    *hwMode = gHashHwMode[mode];
    return DX_RET_OK;
}

/* !
 * Get Hash digest size in bytes.
 *
 * \param mode Hash mode
 * \param digestSize [out] A pointer to the digest size return value
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int GetHashDigestSize(const enum sep_hash_mode mode, uint32_t *digestSize)
{
    if (mode >= SEP_HASH_MODE_NUM) {
        DX_PAL_LOG_ERR("Unsupported hash mode");
        *digestSize = 0;
        return DX_RET_UNSUPP_ALG_MODE;
    }

    *digestSize = gHashDigestSize[mode];
    return DX_RET_OK;
}

/* !
 * Get hardware digest size (HW specific) in bytes.
 *
 * \param mode Hash mode
 * \param hwDigestSize [out] A pointer to the digest size return value
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int GetHashHwDigestSize(const enum sep_hash_mode mode, uint32_t *hwDigestSize)
{
    if (mode >= SEP_HASH_MODE_NUM) {
        DX_PAL_LOG_ERR("Unsupported hash mode");
        *hwDigestSize = 0;
        return DX_RET_UNSUPP_ALG_MODE;
    }

    *hwDigestSize = gHashHwDigestSize[mode];
    return DX_RET_OK;
}

/* !
 * Get Hash block size in bytes.
 *
 * \param mode Hash mode
 * \param blockSize [out] A pointer to the hash block size return value
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int GetHashBlockSize(const enum sep_hash_mode mode, uint32_t *blockSize)
{
    if (mode >= SEP_HASH_MODE_NUM) {
        DX_PAL_LOG_ERR("Unsupported hash mode");
        *blockSize = 0;
        return DX_RET_UNSUPP_ALG_MODE;
    }
    if (mode <= SEP_HASH_SHA224 || mode == SEP_HASH_MD5)
        *blockSize = SEP_SHA1_224_256_BLOCK_SIZE;
    else
        *blockSize = SEP_SHA512_BLOCK_SIZE;
    return DX_RET_OK;
}

/* !
 * Loads the hash digest and hash length to the Hash HW machine.
 *
 * \param qid
 * \param ctxAddr Hash context
 * \param paddingSelection enable/disable Hash block padding by the Hash machine,
 *      should be either HASH_PADDING_DISABLED or HASH_PADDING_ENABLED.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int LoadHashState(int qid, DxSramAddr_t ctxAddr, enum HashConfig1Padding paddingSelection)
{
    const DxSramAddr_t modeAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_hash, mode);
    const DxSramAddr_t digestAddr         = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_hash, digest);
    const DxSramAddr_t k0Addr             = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_hmac, k0);
    const DxSramAddr_t hmacPrivateCtxAddr = (ctxAddr + sizeof(struct sep_ctx_hmac) - sizeof(SepHashPrivateContext_s));
    const DxSramAddr_t hmacFinalizationAddr =
        GET_CTX_FIELD_ADDR(hmacPrivateCtxAddr, SepHashPrivateContext_s, hmacFinalization);
    const DxSramAddr_t currentDigestedLengthAddr =
        GET_CTX_FIELD_ADDR(hmacPrivateCtxAddr, SepHashPrivateContext_s, CurrentDigestedLength);
    DxSramAddr_t tmpSrc = digestAddr;
    uint32_t hw_mode, DigestSize;
    int drvRc = DX_RET_OK;
    HwDesc_s desc;

    drvRc = GetHashHwMode(ReadContextWord(modeAddr), &hw_mode);
    if (drvRc != DX_RET_OK) {
        return drvRc;
    }

    /* SHA224 uses SHA256 HW mode with different init. val. */
    drvRc = GetHashHwDigestSize(ReadContextWord(modeAddr), &DigestSize);
    if (drvRc != DX_RET_OK) {
        return drvRc;
    }

    /* load intermediate hash digest */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);
    if (ReadContextWord(hmacFinalizationAddr) == 1) {
        tmpSrc = k0Addr;
    }
    HW_DESC_SET_STATE_DIN_PARAM(&desc, tmpSrc, DigestSize);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    AddHWDescSequence(qid, &desc);

    /* load the hash current length, should be greater than zero */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, paddingSelection);
    HW_DESC_SET_CIPHER_DO(&desc, DO_NOT_PAD);

    tmpSrc = currentDigestedLengthAddr;
    /* The global array is used to set the HASH current length for HMAC finalization */
    if (ReadContextWord(hmacFinalizationAddr) == 1) {
#ifdef DX_CC_SEP
        tmpSrc = (DxSramAddr_t)((DxVirtAddr_t)gOpadCurrentLength);
#else
        HwDesc_s tdesc;
        uint32_t blockSize;

        /* In non SEP products the OPAD digest length constant is not in the SRAM     */
        /* and it might be non contiguous. In order to overcome this problem the FW   */
        /* copies the values into the CurrentDigestLength field. The coping operation */
        /* must be done with constant descriptors to keep the asynchronious mode working */
        HW_DESC_INIT(&tdesc);
        /* clear the current digest */
        HW_DESC_SET_DIN_CONST(&tdesc, 0, (SEP_HASH_LENGTH_WORDS * sizeof(uint32_t)));
        HW_DESC_SET_STATE_DOUT_PARAM(&tdesc, tmpSrc, (SEP_HASH_LENGTH_WORDS * sizeof(uint32_t)));
        AddHWDescSequence(qid, &tdesc);

        /* set the current length */
        HW_DESC_INIT(&tdesc);
        /* clear the current digest */
        GetHashBlockSize(ReadContextWord(modeAddr), &blockSize);
        HW_DESC_SET_DIN_CONST(&tdesc, blockSize, sizeof(uint32_t));
        HW_DESC_SET_STATE_DOUT_PARAM(&tdesc, tmpSrc, sizeof(uint32_t));
        AddHWDescSequence(qid, &tdesc);
#endif
    }

    HW_DESC_SET_STATE_DIN_PARAM(&desc, tmpSrc, (SEP_HASH_LENGTH_WORDS * sizeof(uint32_t)));
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(qid, &desc);

    return drvRc;
}

/* !
 * Writes the hash digest and hash length back to the Hash context.
 *
 * \param qid
 * \param ctxAddr Hash context
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int StoreHashState(int qid, DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t modeAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_hash, mode);
    const DxSramAddr_t digestAddr         = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_hash, digest);
    const DxSramAddr_t hmacPrivateCtxAddr = (ctxAddr + sizeof(struct sep_ctx_hmac) - sizeof(SepHashPrivateContext_s));
    const DxSramAddr_t currentDigestedLengthAddr =
        GET_CTX_FIELD_ADDR(hmacPrivateCtxAddr, SepHashPrivateContext_s, CurrentDigestedLength);
    uint32_t hw_mode, DigestSize;
    int drvRc = DX_RET_OK;
    HwDesc_s desc;

    drvRc = GetHashHwMode(ReadContextWord(modeAddr), &hw_mode);
    if (drvRc != DX_RET_OK) {
        return drvRc;
    }

    /* SHA224 uses SHA256 HW mode with different init. val. */
    drvRc = GetHashHwDigestSize(ReadContextWord(modeAddr), &DigestSize);
    if (drvRc != DX_RET_OK) {
        return drvRc;
    }

    /* store the hash digest result in the context */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, digestAddr, DigestSize);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    AddHWDescSequence(qid, &desc);

    /* store current hash length in the private context */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, currentDigestedLengthAddr, (SEP_HASH_LENGTH_WORDS * sizeof(uint32_t)));
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
    AddHWDescSequence(qid, &desc);

    return drvRc;
}

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

/* !
 * This function is used to initialize the HASH machine to perform the
 * HASH operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int InitHash(DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t modeAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_hash, mode);
    const DxSramAddr_t digestAddr         = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_hash, digest);
    const DxSramAddr_t hmacPrivateCtxAddr = (ctxAddr + sizeof(struct sep_ctx_hmac) - sizeof(SepHashPrivateContext_s));
    const DxSramAddr_t currentDigestedLengthAddr =
        GET_CTX_FIELD_ADDR(hmacPrivateCtxAddr, SepHashPrivateContext_s, CurrentDigestedLength);
    const DxSramAddr_t dataCompletedAddr =
        GET_CTX_FIELD_ADDR(hmacPrivateCtxAddr, SepHashPrivateContext_s, dataCompleted);
    const DxSramAddr_t hmacFinalizationAddr =
        GET_CTX_FIELD_ADDR(hmacPrivateCtxAddr, SepHashPrivateContext_s, hmacFinalization);

    /* copy the hash initial digest to the user context */
    switch (ReadContextWord(modeAddr)) {
    case SEP_HASH_SHA1:
        WriteContextField(digestAddr, gLarvalSha1Digest, SEP_SHA1_DIGEST_SIZE);
        break;
    case SEP_HASH_SHA224:
        WriteContextField(digestAddr, gLarvalSha224Digest, SEP_SHA256_DIGEST_SIZE);
        break;
    case SEP_HASH_SHA256:
        WriteContextField(digestAddr, gLarvalSha256Digest, SEP_SHA256_DIGEST_SIZE);
        break;
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
    case SEP_HASH_SHA384:
        WriteContextField(digestAddr, gLarvalSha384Digest, SEP_SHA512_DIGEST_SIZE);
        break;
    case SEP_HASH_SHA512:
        WriteContextField(digestAddr, gLarvalSha512Digest, SEP_SHA512_DIGEST_SIZE);
        break;
#endif
    case SEP_HASH_MD5:
        WriteContextField(digestAddr, gLarvalMd5Digest, SEP_MD5_DIGEST_SIZE);
        break;
    default:
        DX_PAL_LOG_ERR("Unsupported hash mode %d\n", ReadContextWord(modeAddr));
        return DX_RET_UNSUPP_ALG_MODE;
    }

    /* clear hash length and load it to the hash machine -we're starting a new transaction */
    ClearCtxField(currentDigestedLengthAddr, (SEP_HASH_LENGTH_WORDS * sizeof(uint32_t)));
    WriteContextWord(dataCompletedAddr, 0);
    WriteContextWord(hmacFinalizationAddr, 0);

    return DX_RET_OK;
}

/* !
 * This function is used to process a block(s) of data on HASH machine.
 * It accepts an input data aligned to hash block size, any reminder which is not
 * aligned should be passed on calling to "FinalizeHash".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int ProcessHash(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    DxDmaAddr_t pInputData = 0;
    HwDesc_s desc;
    uint32_t DataInSize = 0;
    DmaMode_t dmaMode   = NO_DMA;
    uint8_t inAxiNs     = pDmaInputBuffer->axiNs;
    int qid             = CURR_QUEUE_ID(); /* qid is stored in pxTaskTag field */
    int drvRc           = DX_RET_OK;

    HW_DESC_INIT(&desc);

    /* load hash length and digest */
    drvRc = LoadHashState(qid, ctxAddr, HASH_PADDING_DISABLED);
    if (drvRc != DX_RET_OK) {
        goto EndWithErr;
    }

    dmaMode = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);

    /* set the input pointer according to the DMA mode */
    switch (dmaMode) {
    case DMA_MLLI:
        pInputData = GetFirstLliPtr(qid, MLLI_INPUT_TABLE);
        PrepareMLLITable(qid, pDmaInputBuffer->pData, pDmaInputBuffer->size, pDmaInputBuffer->axiNs, MLLI_INPUT_TABLE);
        /* data size should hold the number of LLIs */
        DataInSize = (pDmaInputBuffer->size) / LLI_ENTRY_BYTE_SIZE - 1; // reduce dummy entry (tail)
        break;
    case DMA_DLLI:
    case DMA_SRAM:
        pInputData = pDmaInputBuffer->pData;
        /* set the data size */
        DataInSize = pDmaInputBuffer->size;
        break;
    default:
        DX_PAL_LOG_ERR("Invalid DMA mode\n");
        drvRc = DX_RET_INVARG;
        goto EndWithErr;
    }

    /* process the HASH flow */
    HW_DESC_SET_DIN_TYPE(&desc, dmaMode, pInputData, DataInSize, QID_TO_AXI_ID(qid), inAxiNs);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
    AddHWDescSequence(qid, &desc);

    /* write back digest and hash length */
    StoreHashState(qid, ctxAddr);

EndWithErr:
    return drvRc;
}

/* !
 * This function is used as finish operation of the HASH machine.
 * The function may either be called after "InitHash" or "ProcessHash".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int FinalizeHash(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    const DxSramAddr_t modeAddr   = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_hash, mode);
    const DxSramAddr_t digestAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_hash, digest);
    HwDesc_s desc;
    uint32_t isRemainingData = 0;
    uint32_t DataInSize      = 0;
    DmaMode_t dmaMode        = NO_DMA;
    DxDmaAddr_t pInputData   = 0;
    uint32_t hw_mode;
    uint32_t DigestSize;
    uint8_t inAxiNs = pDmaInputBuffer->axiNs;
    /* qid is stored in pxTaskTag field */
    int qid   = CURR_QUEUE_ID();
    int drvRc = DX_RET_OK;

    HW_DESC_INIT(&desc);

    drvRc = GetHashHwMode(ReadContextWord(modeAddr), &hw_mode);
    if (drvRc != DX_RET_OK) {
        return drvRc;
    }

    /* SHA224 uses SHA256 HW mode with different init. val. */
    /* same for SHA384 with SHA512 */
    drvRc = GetHashHwDigestSize(ReadContextWord(modeAddr), &DigestSize);
    if (drvRc != DX_RET_OK) {
        goto EndWithErr;
    }

    dmaMode = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);

    /* check if we have remaining data to process */
    switch (dmaMode) {
    case DMA_MLLI:
        isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
        DataInSize      = 0;
        break;
    case DMA_DLLI:
    case DMA_SRAM:
        isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
        DataInSize      = pDmaInputBuffer->size;
        break;
    case NO_DMA:
        break;
    default:
        DX_PAL_LOG_ERR("Invalid DMA mode\n");
        drvRc = DX_RET_INVARG;
        goto EndWithErr;
    }

    /* check if there is a remainder */
    if (isRemainingData == 1) {
        /* load hash length and digest */
        drvRc = LoadHashState(qid, ctxAddr, HASH_PADDING_ENABLED);
        if (drvRc != DX_RET_OK) {
            goto EndWithErr;
        }

        /* we have a single MLLI table */
        if (dmaMode == DMA_MLLI) {
            pInputData = GetFirstLliPtr(qid, MLLI_INPUT_TABLE);
            PrepareMLLITable(qid, pDmaInputBuffer->pData, pDmaInputBuffer->size, pDmaInputBuffer->axiNs,
                             MLLI_INPUT_TABLE);
            /* data size should hold the number of LLIs */
            DataInSize = (pDmaInputBuffer->size) / LLI_ENTRY_BYTE_SIZE - 1; // reduce dummy entry (tail)
        } else {
            pInputData = pDmaInputBuffer->pData;
            // check sram!
        }

        /* clobber remaining HASH data */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_DIN_TYPE(&desc, dmaMode, pInputData, DataInSize, QID_TO_AXI_ID(qid), inAxiNs);
        HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
        AddHWDescSequence(qid, &desc);
    } else {
        /* (isRemainingData == 0) */
        const DxSramAddr_t hmacPrivateCtxAddr =
            (ctxAddr + sizeof(struct sep_ctx_hmac) - sizeof(SepHashPrivateContext_s));
        const DxSramAddr_t currentDigestedLengthAddr =
            GET_CTX_FIELD_ADDR(hmacPrivateCtxAddr, SepHashPrivateContext_s, CurrentDigestedLength);

        /* load hash length and digest */
        drvRc = LoadHashState(qid, ctxAddr, HASH_PADDING_DISABLED);
        if (drvRc != DX_RET_OK) {
            goto EndWithErr;
        }

        /* Workaround: do-pad must be enabled only when writing current length to HW */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);
        HW_DESC_SET_CIPHER_CONFIG1(&desc, HASH_PADDING_DISABLED);
        HW_DESC_SET_CIPHER_DO(&desc, DO_PAD);
        HW_DESC_SET_STATE_DOUT_PARAM(&desc, currentDigestedLengthAddr, (SEP_HASH_LENGTH_WORDS * sizeof(uint32_t)));
        HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
        AddHWDescSequence(qid, &desc);
    }

    /* store the hash digest result in the context */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);

    HW_DESC_SET_STATE_DOUT_PARAM(&desc, digestAddr, DigestSize);
    if (hw_mode == SEP_HASH_HW_MD5 || hw_mode == SEP_HASH_HW_SHA512 || hw_mode == SEP_HASH_HW_SHA384) {
        HW_DESC_SET_BYTES_SWAP(&desc, 1);
    } else {
        HW_DESC_SET_CIPHER_CONFIG0(&desc, HASH_DIGEST_RESULT_LITTLE_ENDIAN);
    }
    HW_DESC_SET_CIPHER_CONFIG1(&desc, HASH_PADDING_DISABLED);
    HW_DESC_SET_CIPHER_DO(&desc, DO_NOT_PAD);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    AddHWDescSequence(qid, &desc);

EndWithErr:
    return drvRc;
}
