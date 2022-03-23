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

#include "dx_pal_mem.h"
#include "cc_plat.h"
#include "mlli.h"
#include "hw_queue.h"
#include "completion.h"
#include "dx_error.h"
#include "aead.h"
#include "sep_ctx.h"

DX_PAL_COMPILER_ASSERT(sizeof(struct sep_ctx_aead) == SEP_CTX_SIZE, "sep_ctx_aead is larger than 128 bytes!");
DX_PAL_COMPILER_ASSERT(sizeof(SepAeadCcmMode_e) == sizeof(uint32_t), "SepAeadCcmMode_e is not 32bit!");
DX_PAL_COMPILER_ASSERT(sizeof(SepAeadCcmFlow_e) == sizeof(uint32_t), "SepAeadCcmFlow_e is not 32bit!");

/* *****************************************************************************
 *                PRIVATE FUNCTIONS
 * *************************************************************************** */

static void LoadAeadHeaderMac(int qid, DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t keySizeAddr   = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, key_size);
    const DxSramAddr_t macStateAddr  = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, mac_state);
    const DxSramAddr_t directionAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, direction);
    HwDesc_s desc;

    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, SEP_AEAD_MODE_CCM_A);
    HW_DESC_SET_KEY_SIZE_AES(&desc, ReadContextWord(keySizeAddr));
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, macStateAddr, SEP_AES_BLOCK_SIZE);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, ReadContextWord(directionAddr));
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    AddHWDescSequence(qid, &desc);
}

static void StoreAeadHeaderMac(int qid, DxSramAddr_t ctxAddr)
{
    DxSramAddr_t macStateAddr        = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, mac_state);
    const DxSramAddr_t directionAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, direction);
    HwDesc_s desc;

    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, SEP_AEAD_MODE_CCM_A);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, macStateAddr, SEP_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, S_AES_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, ReadContextWord(directionAddr));
    AddHWDescSequence(qid, &desc);
}

static void LoadAeadCipherMac(int qid, DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t keySizeAddr        = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, key_size);
    const DxSramAddr_t directionAddr      = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, direction);
    const DxSramAddr_t macStateAddr       = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, mac_state);
    const DxSramAddr_t aeadPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, reserved);
    const DxSramAddr_t internalModeAddr = GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, internalMode);
    HwDesc_s desc;

    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, ReadContextWord(internalModeAddr));
    HW_DESC_SET_KEY_SIZE_AES(&desc, ReadContextWord(keySizeAddr));
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES2);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, ReadContextWord(directionAddr));
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, macStateAddr, SEP_AES_BLOCK_SIZE);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, TUNNEL_ON);
    if (ReadContextWord(internalModeAddr) == SEP_AEAD_MODE_CCM_PE) {
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_ENCRYPT_ENCRYPT);
    } else {
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_DECRYPT_ENCRYPT);
    }
    AddHWDescSequence(qid, &desc);
}

static void StoreAeadCipherMac(int qid, DxSramAddr_t ctxAddr)
{
    DxSramAddr_t macStateAddr             = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, mac_state);
    const DxSramAddr_t aeadPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, reserved);
    const DxSramAddr_t internalModeAddr = GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, internalMode);
    HwDesc_s desc;

    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, ReadContextWord(internalModeAddr));
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, macStateAddr, SEP_AES_BLOCK_SIZE);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, TUNNEL_ON);
    HW_DESC_SET_FLOW_MODE(&desc, S_AES2_to_DOUT);
    AddHWDescSequence(qid, &desc);
}

static void LoadAeadCipherState(int qid, DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t keySizeAddr        = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, key_size);
    const DxSramAddr_t blockStateAddr     = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, block_state);
    const DxSramAddr_t aeadPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, reserved);
    const DxSramAddr_t internalModeAddr = GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, internalMode);
    HwDesc_s desc;

    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, ReadContextWord(internalModeAddr));
    HW_DESC_SET_KEY_SIZE_AES(&desc, ReadContextWord(keySizeAddr));
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, blockStateAddr, SEP_AES_BLOCK_SIZE);
    if (ReadContextWord(internalModeAddr) == SEP_AEAD_MODE_CCM_PE) {
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_ENCRYPT_ENCRYPT);
    } else {
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_DECRYPT_ENCRYPT);
    }
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, TUNNEL_ON);
    AddHWDescSequence(qid, &desc);
}

static void StoreAeadCipherState(int qid, DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t blockStateAddr     = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, block_state);
    const DxSramAddr_t aeadPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, reserved);
    const DxSramAddr_t internalModeAddr = GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, internalMode);
    HwDesc_s desc;

    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, ReadContextWord(internalModeAddr));
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, blockStateAddr, SEP_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, S_AES_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, TUNNEL_ON);
    if (ReadContextWord(internalModeAddr) == SEP_AEAD_MODE_CCM_PE) {
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_ENCRYPT_ENCRYPT);
    } else {
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_DECRYPT_ENCRYPT);
    }
    AddHWDescSequence(qid, &desc);
}

static void LoadAeadKey(int qid, DxSramAddr_t ctxAddr, FlowMode_t engineFlow, TunnelOp_t isTunnel)
{
    const DxSramAddr_t keyAddr            = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, key);
    const DxSramAddr_t keySizeAddr        = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, key_size);
    const DxSramAddr_t aeadPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, reserved);
    const DxSramAddr_t internalModeAddr = GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, internalMode);
    uint32_t keySize                    = ReadContextWord(keySizeAddr);
    HwDesc_s desc;

    /* key size 24 bytes count as 32 bytes, make sure to zero wise upper 8 bytes */
    if (keySize == 24) {
        keySize = SEP_AES_KEY_SIZE_MAX;
        ClearCtxField((keyAddr + 24), SEP_AES_KEY_SIZE_MAX - 24);
    }

    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, ReadContextWord(internalModeAddr));
    HW_DESC_SET_KEY_SIZE_AES(&desc, ReadContextWord(keySizeAddr));
    HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, keySize);
    HW_DESC_SET_FLOW_MODE(&desc, engineFlow);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, isTunnel);

    if (ReadContextWord(internalModeAddr) == SEP_AEAD_MODE_CCM_PE) {
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_ENCRYPT_ENCRYPT);
    } else {
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_DECRYPT_ENCRYPT);
    }
    AddHWDescSequence(qid, &desc);
}

static uint16_t FormatCcmB0(uint8_t *Buf, uint8_t *Nonce, uint32_t NonceSize, uint32_t Tag, uint32_t AddDataSize,
                            uint32_t InputDataLen)
{
    uint32_t len, Q, x, y;

    /* let's get the L value */
    len = InputDataLen;
    Q   = 0;

    while (len) {
        ++Q;
        len >>= 8;
    }

    if (Q <= 1) {
        Q = 2;
    }

    /* increase L to match the nonce len */
    NonceSize = (NonceSize > 13) ? 13 : NonceSize;
    if ((15 - NonceSize) > Q) {
        Q = 15 - NonceSize;
    }

    /* form B_0 == flags | Nonce N | l(m) */
    x        = 0;
    Buf[x++] = (unsigned char)(((AddDataSize > 0) ? (1 << 6) : 0) | (((Tag - 2) >> 1) << 3) | (Q - 1));

    /* nonce */
    for (y = 0; y < (16 - (Q + 1)); y++) {
        Buf[x++] = Nonce[y];
    }

    /* store len */
    len = InputDataLen;

    /* shift len so the upper bytes of len are the contents of the length */
    for (y = Q; y < 4; y++) {
        len <<= 8;
    }

    /* store l(m) (only store 32-bits) */
    for (y = 0; Q > 4 && (Q - y) > 4; y++) {
        Buf[x++] = 0;
    }

    for (; y < Q; y++) {
        Buf[x++] = (unsigned char)((len >> 24) & 0xFF);
        len <<= 8;
    }

    return (uint16_t)Q;
}

static void InitCcmCounter(int qid, DxSramAddr_t ctxAddr, uint8_t CounterInitialValue)
{
    const DxSramAddr_t nonceAddr          = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, nonce);
    DxSramAddr_t blockStateAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, block_state);
    const DxSramAddr_t aeadPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, reserved);
    const DxSramAddr_t qAddr              = GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, q);

    uint32_t Q         = ReadContextWord(qAddr);
    uint32_t nonceSize = SEP_AES_BLOCK_SIZE - (Q + 1);
    uint32_t word      = 0; /* work buffer */
    uint8_t *p         = (uint8_t *)&word;
    int i = 0, j = 0;
    HwDesc_s desc;
    uint32_t nonceBuff[SEP_AES_BLOCK_SIZE_WORDS];
    uint8_t *nonce = (uint8_t *)&nonceBuff;

#ifdef DX_CC_SRAM_INDIRECT_ACCESS
    ReadContextField(nonceAddr, nonceBuff, SEP_AES_BLOCK_SIZE);
#else
    DX_PAL_MemCopy(nonceBuff, nonceAddr, SEP_AES_BLOCK_SIZE);
#endif

    p[0] = (unsigned char)Q - 1;
    p[1] = nonce[j++];
    p[2] = nonce[j++];
    p[3] = nonce[j++];

    word = SWAP_TO_LE(word);
    /* set 1B flags + 3B of the nonce */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_CONST(&desc, word, sizeof(uint32_t));
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, blockStateAddr, sizeof(uint32_t));
    HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
    AddHWDescSequence(qid, &desc);

    /* set nonce */
    for (i = 4; j < nonceSize; i += 4) {
        p[0] = nonce[j++];
        p[1] = (j < nonceSize) ? nonce[j++] : 0;
        p[2] = (j < nonceSize) ? nonce[j++] : 0;
        p[3] = (j < nonceSize) ? nonce[j++] : 0;

        /* this is the last word so set the counter value
           as passed by the user in the LSB. The nonce value
           cannot reache the last byte */
        if (i == (SEP_AES_BLOCK_SIZE - sizeof(uint32_t))) {
            p[3] = CounterInitialValue;
        }

        word = SWAP_TO_LE(word);

        HW_DESC_INIT(&desc);
        HW_DESC_SET_DIN_CONST(&desc, word, sizeof(uint32_t));
        HW_DESC_SET_STATE_DOUT_PARAM(&desc, (blockStateAddr + i), sizeof(uint32_t));
        HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
        AddHWDescSequence(qid, &desc);
    }

    /* pad remainder with zero's */
    for (; i < SEP_AES_BLOCK_SIZE; i += 4) {
        word = 0; /* clear word */

        if (i == (SEP_AES_BLOCK_SIZE - sizeof(uint32_t))) {
            /* this is the last word so set the counter value
             *  as passed by the user in the LSB */
            p[3] = CounterInitialValue;
        }
        word = SWAP_TO_LE(word);

        HW_DESC_INIT(&desc);
        HW_DESC_SET_DIN_CONST(&desc, word, sizeof(uint32_t));
        HW_DESC_SET_STATE_DOUT_PARAM(&desc, (blockStateAddr + i), sizeof(uint32_t));
        HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
        AddHWDescSequence(qid, &desc);
    }
}

static void GetFinalCcmMac(int qid, DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t keyAddr        = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, key);
    const DxSramAddr_t keySizeAddr    = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, key_size);
    const DxSramAddr_t blockStateAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, block_state);
    DxSramAddr_t macStateAddr         = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, mac_state);
    const DxSramAddr_t tagSizeAddr    = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, tag_size);
    uint32_t keySize                  = ReadContextWord(keySizeAddr);
    HwDesc_s desc;

    /* key size 24 bytes count as 32 bytes, make sure to zero wise upper 8 bytes */
    if (keySize == 24) {
        keySize = SEP_AES_KEY_SIZE_MAX;
        ClearCtxField((keyAddr + 24), SEP_AES_KEY_SIZE_MAX - 24);
    }

    /* initialize CTR counter */
    InitCcmCounter(qid, ctxAddr, 0);

    /* load AES-CTR state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, SEP_CIPHER_CTR);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
    HW_DESC_SET_KEY_SIZE_AES(&desc, keySize);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, SEP_CRYPTO_DIRECTION_ENCRYPT);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, blockStateAddr, SEP_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    AddHWDescSequence(qid, &desc);

    /* load AES-CTR key */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, SEP_CIPHER_CTR);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, SEP_CRYPTO_DIRECTION_ENCRYPT);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, keySize);
    HW_DESC_SET_KEY_SIZE_AES(&desc, ReadContextWord(keySizeAddr));
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(qid, &desc);

    /* encrypt the "T" value and store MAC in mac_state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, macStateAddr, ReadContextWord(tagSizeAddr));
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, macStateAddr, ReadContextWord(tagSizeAddr));
    HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
    AddHWDescSequence(qid, &desc);
}

static uint32_t GetActualHeaderSize(uint32_t headerSize)
{
    if (headerSize == 0) {
        return 0;
    } else if (headerSize < ((1UL << 16) - (1UL << 8))) {
        return (2 + headerSize);
    } else {
        return (6 + headerSize);
    }
}

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

/* !
 * This function is used to initialize the AES machine to perform
 * the AEAD operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int InitAead(DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t modeAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, mode);
    const DxSramAddr_t nonceAddr          = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, nonce);
    const DxSramAddr_t nonceSizeAddr      = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, nonce_size);
    const DxSramAddr_t tagSizeAddr        = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, tag_size);
    const DxSramAddr_t headerSizeAddr     = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, header_size);
    const DxSramAddr_t textSizeAddr       = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, text_size);
    const DxSramAddr_t blockStateAddr     = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, block_state);
    const DxSramAddr_t macStateAddr       = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, mac_state);
    const DxSramAddr_t aeadPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, reserved);
    const DxSramAddr_t internalModeAddr = GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, internalMode);
    const DxSramAddr_t nextProcessingStateAddr =
        GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, nextProcessingState);
    const DxSramAddr_t headerRemainingBytesAddr =
        GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, headerRemainingBytes);
    const DxSramAddr_t qAddr = GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, q);
    HwDesc_s desc;

    /* qid is stored in pxTaskTag field */
    int qid = CURR_QUEUE_ID();
#ifdef DX_CC_SRAM_INDIRECT_ACCESS
    uint32_t nonceBuff[SEP_AES_BLOCK_SIZE_WORDS];
    uint8_t *nonce = (uint8_t *)&nonceBuff;
    uint32_t stateBuff[SEP_AES_BLOCK_SIZE_WORDS];
#endif
    switch (ReadContextWord(modeAddr)) {
    case SEP_CIPHER_CCM:
        /* set AES-CCM internal mode: initial state */
        WriteContextWord(internalModeAddr, SEP_AEAD_MODE_CCM_A);
        if (ReadContextWord(headerSizeAddr) == 0) {
            WriteContextWord(nextProcessingStateAddr, SEP_AEAD_FLOW_TEXT_DATA_INIT);
        } else {
            WriteContextWord(nextProcessingStateAddr, SEP_AEAD_FLOW_ADATA_INIT);
        }

        /* clear AES CTR/MAC states */
        ClearCtxField(blockStateAddr, SEP_AES_BLOCK_SIZE);
        ClearCtxField(macStateAddr, SEP_AES_BLOCK_SIZE);
        WriteContextWord(headerRemainingBytesAddr, GetActualHeaderSize(ReadContextWord(headerSizeAddr)));

#ifdef DX_CC_SRAM_INDIRECT_ACCESS
        ReadContextField(nonceAddr, nonceBuff, SEP_AES_BLOCK_SIZE);
        WriteContextWord(qAddr, FormatCcmB0((uint8_t *)stateBuff, nonce, ReadContextWord(nonceSizeAddr),
                                            ReadContextWord(tagSizeAddr), ReadContextWord(headerSizeAddr),
                                            ReadContextWord(textSizeAddr)));
        WriteContextField(blockStateAddr, stateBuff, SEP_AES_BLOCK_SIZE);
#else
        pAeadPrivateCtx->q =
            FormatCcmB0(blockStateAddr, nonceAddr, nonceSizeAddr, tagSizeAddr, headerSizeAddr, textSizeAddr);
#endif
        /* format B0 header */

        /* calc MAC signature on B0 header */
        LoadAeadHeaderMac(qid, ctxAddr);
        LoadAeadKey(qid, ctxAddr, S_DIN_to_AES, TUNNEL_OFF);

        HW_DESC_INIT(&desc);
        HW_DESC_SET_STATE_DIN_PARAM(&desc, blockStateAddr, SEP_AES_BLOCK_SIZE);
        HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
        AddHWDescSequence(qid, &desc);

        /* MAC result stored in mac_state */
        StoreAeadHeaderMac(qid, ctxAddr);

        break;
    default:
        DX_PAL_LOG_ERR("Alg mode not supported");
        return DX_RET_UNSUPP_ALG;
    }

    return DX_RET_OK;
}

/* !
 * This function is used to process a block(s) of data on AES machine.
 * The user must process any associated data followed by the text data
 * blocks. This function MUST be called after the InitCipher function.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int ProcessAead(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    DxDmaAddr_t pInputData = 0, pOutputData = 0;
    uint32_t DataInSize = 0, DataOutSize = 0;
    HwDesc_s desc;
    DmaMode_t dmaInMode                   = NO_DMA;
    DmaMode_t dmaOutMode                  = NO_DMA;
    uint8_t inAxiNs                       = pDmaInputBuffer->axiNs;
    uint8_t outAxiNs                      = pDmaOutputBuffer->axiNs;
    const DxSramAddr_t modeAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, mode);
    const DxSramAddr_t headerSizeAddr     = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, header_size);
    const DxSramAddr_t directionAddr      = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, direction);
    const DxSramAddr_t aeadPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, reserved);
    const DxSramAddr_t nextProcessingStateAddr =
        GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, nextProcessingState);
    const DxSramAddr_t headerRemainingBytesAddr =
        GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, headerRemainingBytes);
    const DxSramAddr_t internalModeAddr = GET_CTX_FIELD_ADDR(aeadPrivateCtxAddr, SepAeadPrivateContext_s, internalMode);
    const int isInplaceOp =
        ((pDmaInputBuffer->pData == pDmaOutputBuffer->pData) ||
         (ReadContextWord(nextProcessingStateAddr) == SEP_AEAD_FLOW_ADATA_INIT) ||
         (ReadContextWord(nextProcessingStateAddr) == SEP_AEAD_FLOW_ADATA_PROCESS) || (pDmaOutputBuffer->pData == 0));
    int qid   = CURR_QUEUE_ID(); /* qid is stored in pxTaskTag field */
    int drvRc = DX_RET_OK;

    if (ReadContextWord(modeAddr) != SEP_CIPHER_CCM) {
        DX_PAL_LOG_ERR("Alg mode not supported");
        drvRc = DX_RET_UNSUPP_ALG;
        goto EndWithErr;
    }

    dmaInMode  = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);
    dmaOutMode = DMA_BUF_TYPE_TO_MODE(pDmaOutputBuffer->dmaBufType);

    switch (ReadContextWord(nextProcessingStateAddr)) {
    case SEP_AEAD_FLOW_ADATA_INIT:
        /* set the next flow sate */
        if (dmaInMode == DMA_MLLI) {
            /* if MLLI -we expect to have the all header at once,
             *  could be one table or more but in a single descriptor processing */
            WriteContextWord(nextProcessingStateAddr, SEP_AEAD_FLOW_TEXT_DATA_INIT);
            WriteContextWord(headerRemainingBytesAddr,
                             ReadContextWord(headerRemainingBytesAddr) - ReadContextWord(headerSizeAddr));
        } else {
            /* if SRAM or DLLI -user may process his associated data in a partial AES blocks */
            WriteContextWord(nextProcessingStateAddr, SEP_AEAD_FLOW_ADATA_PROCESS);
        }

        /* initialize AES-CTR counter only once */
        InitCcmCounter(qid, ctxAddr, 1);

        /* load mac state and key */
        LoadAeadHeaderMac(qid, ctxAddr);
        LoadAeadKey(qid, ctxAddr, S_DIN_to_AES, TUNNEL_OFF);
        break;
    case SEP_AEAD_FLOW_ADATA_PROCESS:
        /* set the next flow sate */
        if (dmaInMode == DMA_MLLI) {
#ifndef DX_CC_TEE
            DX_PAL_LOG_ERR("ILLEGAL flow: associated data should passed at once (DMA_MLLI)");
            drvRc = DX_RET_PERM;
            goto EndWithErr;
#else
            WriteContextWord(nextProcessingStateAddr, SEP_AEAD_FLOW_TEXT_DATA_INIT);
            WriteContextWord(headerRemainingBytesAddr,
                             ReadContextWord(headerRemainingBytesAddr) - ReadContextWord(headerSizeAddr));
#endif
        }

        LoadAeadHeaderMac(qid, ctxAddr);
        LoadAeadKey(qid, ctxAddr, S_DIN_to_AES, TUNNEL_OFF);
        break;
    case SEP_AEAD_FLOW_TEXT_DATA_INIT:
        /* set internal mode: CCM encrypt/decrypt */
        WriteContextWord(internalModeAddr, SEP_AEAD_CCM_SET_INTERNAL_MODE(ReadContextWord(directionAddr)));
        WriteContextWord(nextProcessingStateAddr, SEP_AEAD_FLOW_TEXT_DATA_PROCESS);
        /* initialize AES-CTR counter only once */
        InitCcmCounter(qid, ctxAddr, 1);
        /* FALLTHROUGH */
    case SEP_AEAD_FLOW_TEXT_DATA_PROCESS:
    default:
        LoadAeadKey(qid, ctxAddr, S_DIN_to_AES, TUNNEL_ON);
        LoadAeadCipherState(qid, ctxAddr);
        LoadAeadCipherMac(qid, ctxAddr);
        LoadAeadKey(qid, ctxAddr, S_DIN_to_AES2, TUNNEL_ON);
        break;
    }

    switch (dmaInMode) {
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

    if (isInplaceOp) {
        pOutputData = pInputData;
        DataOutSize = DataInSize;
    } else {
        switch (dmaOutMode) {
        case DMA_MLLI:
            /* get OUT MLLI tables pointer in SRAM (if not inplace operation) */
            pOutputData = GetFirstLliPtr(qid, MLLI_OUTPUT_TABLE);
            PrepareMLLITable(qid, pDmaOutputBuffer->pData, pDmaOutputBuffer->size, pDmaOutputBuffer->axiNs,
                             MLLI_OUTPUT_TABLE);
            /* data size should hold the number of LLIs */
            DataOutSize = (pDmaOutputBuffer->size) / LLI_ENTRY_BYTE_SIZE - 1; // reduce dummy entry (tail)
            break;
        case DMA_DLLI:
        case DMA_SRAM:
            pOutputData = pDmaOutputBuffer->pData;
            /* set the data size */
            DataOutSize = pDmaOutputBuffer->size;
            break;
        default:
            if (ReadContextWord(internalModeAddr) != SEP_AEAD_MODE_CCM_A) {
                DX_PAL_LOG_ERR("Invalid DMA mode\n");
                drvRc = DX_RET_INVARG;
                goto EndWithErr;
            }
        }
    }

    /* process the AEAD flow */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_TYPE(&desc, dmaInMode, pInputData, DataInSize, QID_TO_AXI_ID(qid), inAxiNs);
    if (ReadContextWord(internalModeAddr) != SEP_AEAD_MODE_CCM_A) {
        HW_DESC_SET_DOUT_TYPE(&desc, dmaOutMode, pOutputData, DataOutSize, QID_TO_AXI_ID(qid), outAxiNs);
    }
    HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
    AddHWDescSequence(qid, &desc);

    /* store machine state */
    if (ReadContextWord(internalModeAddr) == SEP_AEAD_MODE_CCM_A) {
        StoreAeadHeaderMac(qid, ctxAddr);

        if ((dmaInMode == DMA_DLLI) || (dmaInMode == DMA_SRAM)) {
            WriteContextWord(headerRemainingBytesAddr,
                             ReadContextWord(headerRemainingBytesAddr) - pDmaInputBuffer->size);
            if (ReadContextWord(headerRemainingBytesAddr) > ReadContextWord(headerSizeAddr)) {
                DX_PAL_LOG_ERR("Inconceivable state: Assoc remaining bytes > Header size");
                drvRc = DX_RET_NOEXEC;
                goto EndWithErr;
            }
            if (ReadContextWord(headerRemainingBytesAddr) == 0) {
                /* we're done processing associated data move on to text initialization flow */
                WriteContextWord(nextProcessingStateAddr, SEP_AEAD_FLOW_TEXT_DATA_INIT);
            }
        }
    } else {
        StoreAeadCipherState(qid, ctxAddr);
        StoreAeadCipherMac(qid, ctxAddr);
    }

EndWithErr:
    return drvRc;
}

/* !
 * This function is used as finish operation of AEAD. The function MUST either
 * be called after "InitCipher" or "ProcessCipher".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int FinalizeAead(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    const DxSramAddr_t modeAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct sep_ctx_aead, mode);
    uint32_t isRemainingData    = 0;
    DmaMode_t dmaMode           = NO_DMA;
    int qid                     = CURR_QUEUE_ID();
    int drvRc                   = DX_RET_OK;

    if (ReadContextWord(modeAddr) != SEP_CIPHER_CCM) {
        DX_PAL_LOG_ERR("Alg mode not supported");
        drvRc = DX_RET_UNSUPP_ALG;
        goto EndWithErr;
    }

    dmaMode = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);

    /* check if we have remaining data to process */
    switch (dmaMode) {
    case DMA_MLLI:
        isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
        break;
    case DMA_DLLI:
    case DMA_SRAM:
        isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
        break;
    case NO_DMA:
        break;
    default:
        DX_PAL_LOG_ERR("Invalid DMA mode\n");
        drvRc = DX_RET_INVARG;
        goto EndWithErr;
    }

    /* clobber remaining AEAD data */
    if (isRemainingData) {
        /* process all tables and get state from the AES machine */
        drvRc = ProcessAead(ctxAddr, pDmaInputBuffer, pDmaOutputBuffer);
        if (drvRc != DX_RET_OK) {
            goto EndWithErr;
        }
    }

    /* get the CCM-MAC result */
    GetFinalCcmMac(qid, ctxAddr);

EndWithErr:
    return drvRc;
}
