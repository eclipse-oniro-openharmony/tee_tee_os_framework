/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_SaSi_SYM_DRIVER

#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "sym_crypto_driver.h"
#include "ssi_error.h"
#include "cc_plat.h"
#include "mlli.h"
#include "hw_queue.h"
#include "ssi_crypto_ctx.h"
#include "completion.h"
#include "hash.h"
#include "hmac.h"
#include "hmac_defs.h"

SASI_PAL_COMPILER_ASSERT(sizeof(struct drv_ctx_hmac) == SEP_CTX_SIZE, "drv_ctx_hmac is larger than 128 bytes!");
SASI_PAL_COMPILER_ASSERT(sizeof(ZeroBlock) >= (SEP_HASH_LENGTH_WORDS * sizeof(uint32_t)),
                         "ZeroBlock is too small for HASH_LENGTH field init.");
SASI_PAL_COMPILER_ASSERT(sizeof(ZeroBlock) >= SEP_AES_128_BIT_KEY_SIZE, "ZeroBlock is too small for key field init.");

/* *****************************************************************************
 *                GLOBALS
 * *************************************************************************** */
extern const uint32_t gLarvalSha1Digest[];
extern const uint32_t gLarvalSha224Digest[];
extern const uint32_t gLarvalSha256Digest[];
extern const uint32_t gLarvalMd5Digest[];
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
extern const uint32_t gLarvalSha384Digest[];
extern const uint32_t gLarvalSha512Digest[];
#endif

const uint32_t gOpadDecrypedBlock[] SASI_SRAM_CONST = { HMAC_DECRYPTED_OPAD_CONST_BLOCK };
const uint32_t gIpadDecrypedBlock[] SASI_SRAM_CONST = { HMAC_DECRYPTED_IPAD_CONST_BLOCK };
#define HMAC_IPAD_CONST_BLOCK 0x36363636
#define HMAC_OPAD_CONST_BLOCK 0x5C5C5C5C

/* *****************************************************************************
 *                PRIVATE FUNCTIONS
 * *************************************************************************** */

static int ProcessHmacPad(int qid, uint32_t constPadData, DxSramAddr_t hashData, uint32_t hashDataSize,
                          enum sep_hash_mode hmode, DxSramAddr_t hashCurrentLength, DxSramAddr_t hashResult,
                          DxSramAddr_t ctxAddr)
{
    HwDesc_s desc;
    uint32_t lhmode;
    uint32_t DigestSize;
    DxSramAddr_t digestAddr;
    int drvRc = SASI_RET_OK;

    drvRc = GetHashHwMode(hmode, &lhmode);
    if (drvRc != SASI_RET_OK) {
        return drvRc;
    }

    /* SHA224 uses SHA256 HW mode with different init. val. */
    drvRc = GetHashHwDigestSize(hmode, &DigestSize);
    if (drvRc != SASI_RET_OK) {
        return drvRc;
    }

#ifdef DX_CC_SRAM_INDIRECT_ACCESS
    /* get the SRAM address right after the context cache */
    digestAddr = (ctxAddr + SEP_CTX_SIZE);

    switch (hmode) {
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
    case SEP_HASH_MD5:
        WriteContextField(digestAddr, gLarvalMd5Digest, SEP_MD5_DIGEST_SIZE);
        break;
#endif
    default:
        SASI_PAL_LOG_ERR("Unsupported hash mode %d\n", hmode);
        return SASI_RET_UNSUPP_ALG_MODE;
    }
#else
    switch (hmode) {
    case SEP_HASH_SHA1:
        digestAddr = (DxSramAddr_t)((SaSiVirtAddr_t)gLarvalSha1Digest);
        break;
    case SEP_HASH_SHA224:
        digestAddr = (DxSramAddr_t)((SaSiVirtAddr_t)gLarvalSha224Digest);
        break;
    case SEP_HASH_SHA256:
        digestAddr = (DxSramAddr_t)((SaSiVirtAddr_t)gLarvalSha256Digest);
        break;
    case SEP_HASH_MD5:
        digestAddr = (DxSramAddr_t)((SaSiVirtAddr_t)gLarvalMd5Digest);
        break;
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
    case SEP_HASH_SHA384:
        digestAddr = (DxSramAddr_t)((SaSiVirtAddr_t)gLarvalSha384Digest);
        break;
    case SEP_HASH_SHA512:
        digestAddr = (DxSramAddr_t)((SaSiVirtAddr_t)gLarvalSha512Digest);
        break;
#endif
    default:
        SASI_PAL_LOG_ERR("Unsupported hash mode %d\n", hmode);
        return SASI_RET_UNSUPP_ALG_MODE;
    }
#endif

    /* 1. Load hash initial state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, digestAddr, DigestSize);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    AddHWDescSequence(qid, &desc);

    /* 2. load the hash current length, should be greater than zero */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_DIN_CONST(&desc, 0, (SEP_HASH_LENGTH_WORDS * sizeof(uint32_t)));
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(qid, &desc);

    /* 3. prapare pad key - IPAD or OPAD */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_XOR_VAL(&desc, constPadData);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
    AddHWDescSequence(qid, &desc);

    /* 4. perform HASH update */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, hashData, hashDataSize);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_XOR_ACTIVE(&desc);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
    AddHWDescSequence(qid, &desc);

    /* 5. Get the digset */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, hashResult, DigestSize);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    AddHWDescSequence(qid, &desc);

    /* 6. store current hash length in the private context */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, lhmode);
    HW_DESC_SET_CIPHER_DO(&desc, DO_NOT_PAD);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, hashCurrentLength, sizeof(uint32_t) * SEP_HASH_LENGTH_WORDS);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
    AddHWDescSequence(qid, &desc);

    return SASI_RET_OK;
}

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

/* !
 * This function is used to initialize the HMAC machine to perform the HMAC
 * operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int InitHmac(DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t modeAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hmac, mode);
    const DxSramAddr_t digestAddr         = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hmac, digest);
    const DxSramAddr_t k0Addr             = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hmac, k0);
    const DxSramAddr_t k0SizeAddr         = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hmac, k0_size);
    const DxSramAddr_t hmacPrivateCtxAddr = (ctxAddr + sizeof(struct drv_ctx_hmac) - sizeof(SepHashPrivateContext_s));
    const DxSramAddr_t currentDigestedLengthAddr =
        GET_CTX_FIELD_ADDR(hmacPrivateCtxAddr, SepHashPrivateContext_s, CurrentDigestedLength);
    uint32_t BlockSize, KeySize;
    int qid   = CURR_QUEUE_ID();
    int drvRc = SASI_RET_OK;

    drvRc = GetHashBlockSize(ReadContextWord(modeAddr), &BlockSize);
    if (drvRc != SASI_RET_OK) {
        goto EndWithErr;
    }

    /* pad the key with zeros */
    KeySize = ReadContextWord(k0SizeAddr);
#ifndef DX_CC_SRAM_INDIRECT_ACCESS
    ClearCtxField((k0Addr + KeySize), (BlockSize - KeySize));
#else
    /* due to the limited access to the SRAM (words alignment)the key shold be Read/Modify/Write if the key is not
     * aligned to words */
    if (!(KeySize % sizeof(uint32_t))) {
        ClearCtxField((k0Addr + KeySize), (BlockSize - KeySize));
    } else {
        uint32_t keywords[SEP_SHA512_BLOCK_SIZE / sizeof(uint32_t)];
        /* read the whole key and write it back */
        /* T.B.D - optimize this sequence to one word only */
        ReadContextField(k0Addr, keywords, BlockSize);
        SaSi_PalMemSetZero(&((uint8_t *)&keywords[0])[KeySize], (BlockSize - KeySize));
        WriteContextField(k0Addr, keywords, BlockSize);
    }
#endif
    drvRc = InitHash(ctxAddr);
    if (drvRc != SASI_RET_OK) {
        goto EndWithErr;
    }

    drvRc = ProcessHmacPad(qid, HMAC_IPAD_CONST_BLOCK, k0Addr, BlockSize, ReadContextWord(modeAddr),
                           currentDigestedLengthAddr, digestAddr, ctxAddr);
    if (drvRc != SASI_RET_OK) {
        goto EndWithErr;
    }
    drvRc = ProcessHmacPad(qid, HMAC_OPAD_CONST_BLOCK, k0Addr, BlockSize, ReadContextWord(modeAddr),
                           currentDigestedLengthAddr, k0Addr, ctxAddr);
    if (drvRc != SASI_RET_OK) {
        goto EndWithErr;
    }

EndWithErr:
    return drvRc;
}

/* ***************************************************************************** */
/* ***************************************************************************** */
/* !! we do not implement "ProcessHmac" since it directly calls ProcessHash     */
/* ***************************************************************************** */
/* ***************************************************************************** */

/* !
 * This function is used as finish operation of the HMAC machine.
 * The function may be called after "InitHmac".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int FinalizeHmac(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    const DxSramAddr_t modeAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hmac, mode);
    const DxSramAddr_t digestAddr         = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_hmac, digest);
    const DxSramAddr_t hmacPrivateCtxAddr = (ctxAddr + sizeof(struct drv_ctx_hmac) - sizeof(SepHashPrivateContext_s));
    const DxSramAddr_t hmacFinalizationAddr =
        GET_CTX_FIELD_ADDR(hmacPrivateCtxAddr, SepHashPrivateContext_s, hmacFinalization);
    DmaBuffer_s HashDmaBuffer;
    uint32_t DigestSize;
    int drvRc = SASI_RET_OK;

    SASI_UNUSED_PARAM(pDmaOutputBuffer); // remove compilation warning
    drvRc = GetHashDigestSize(ReadContextWord(modeAddr), &DigestSize);
    if (drvRc != SASI_RET_OK) {
        goto EndWithErr;
    }

    /* finalize user data (data may be zero length) */
    drvRc = FinalizeHash(ctxAddr, pDmaInputBuffer, NULL);
    if (drvRc != SASI_RET_OK) {
        goto EndWithErr;
    }

    WriteContextWord(hmacFinalizationAddr, 1);

    HashDmaBuffer.pData      = digestAddr;
    HashDmaBuffer.size       = DigestSize;
    HashDmaBuffer.dmaBufType = DMA_BUF_SEP;
    HashDmaBuffer.axiNs      = DEFALUT_AXI_SECURITY_MODE;

    drvRc = FinalizeHash(ctxAddr, &HashDmaBuffer, NULL);

EndWithErr:
    return drvRc;
}
