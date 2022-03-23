/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_SaSi_SYM_DRIVER

#include "ssi_pal_mem.h"
#include "ssi_pal_log.h"
#include "cc_plat.h"
#include "mlli.h"
#include "cipher.h"
#include "ssi_crypto_ctx.h"
#include "hw_queue.h"
#include "ssi_error.h"
#include "ssi_hal_plat.h"
#include "sym_crypto_driver.h"
#ifdef DX_CC_SEP
#include "timing.h"
#else
#define TIMING_MARK(index)
#endif

SASI_PAL_COMPILER_ASSERT(sizeof(struct drv_ctx_cipher) == SEP_CTX_SIZE, "drv_ctx_cipher is larger than 128 bytes!");
SASI_PAL_COMPILER_ASSERT(sizeof(enum sep_cipher_mode) == sizeof(uint32_t), "sep_cipher_mode is not 32bit!");
SASI_PAL_COMPILER_ASSERT(sizeof(DataBlockType_t) == sizeof(uint32_t), "DataBlockType_t is not 32bit!");
SASI_PAL_COMPILER_ASSERT(sizeof(SepAesCoreEngine_t) == sizeof(uint32_t), "SepAesCoreEngine_t is not 32bit!");

/* *****************************************************************************
 *                PRIVATE FUNCTIONS
 * *************************************************************************** */

void LoadCipherState(int qid, DxSramAddr_t ctxAddr, uint8_t is_zero_iv)
{
    const DxSramAddr_t modeAddr          = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, mode);
    const DxSramAddr_t algAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, alg);
    const DxSramAddr_t keySizeAddr       = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key_size);
    const DxSramAddr_t directionAddr     = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, direction);
    const DxSramAddr_t blockStateAddr    = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, block_state);
    const DxSramAddr_t aesPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, reserved);
    const DxSramAddr_t isTunnelOpAddr    = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, isTunnelOp);
    const DxSramAddr_t tunnetDirAddr     = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, tunnetDir);
    const DxSramAddr_t engineCoreAddr    = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, engineCore);
    HwDesc_s desc;
    uint32_t blockSize;

    HW_DESC_INIT(&desc);

    switch (ReadContextWord(modeAddr)) {
    case SEP_CIPHER_ECB:
        return;
    case SEP_CIPHER_CTR:
    case SEP_CIPHER_XTS:
    case SEP_CIPHER_OFB:
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
        break;
    default:
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    }

    HW_DESC_SET_CIPHER_MODE(&desc, ReadContextWord(modeAddr));
    if (ReadContextWord(algAddr) == DRV_CRYPTO_ALG_AES) {
        blockSize = SEP_AES_BLOCK_SIZE;
        HW_DESC_SET_CIPHER_CONFIG0(&desc, ReadContextWord(isTunnelOpAddr) ? ReadContextWord(tunnetDirAddr) :
                                                                            ReadContextWord(directionAddr));
        HW_DESC_SET_KEY_SIZE_AES(&desc, ReadContextWord(keySizeAddr));
        HW_DESC_SET_CIPHER_CONFIG1(&desc, ReadContextWord(isTunnelOpAddr));
        if (ReadContextWord(engineCoreAddr) == SEP_AES_ENGINE2) {
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES2);
        } else {
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
        }
    } else { /* DES */
        blockSize = SASI_DRV_DES_IV_SIZE;
        HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_DES);
        HW_DESC_SET_CIPHER_CONFIG0(&desc, ReadContextWord(directionAddr));
        HW_DESC_SET_KEY_SIZE_DES(&desc, ReadContextWord(keySizeAddr));
    }
    /* if is_zero_iv use ZeroBlock as IV */
    if (is_zero_iv == 1) {
        HW_DESC_SET_DIN_CONST(&desc, 0, blockSize);
    } else {
        HW_DESC_SET_STATE_DIN_PARAM(&desc, blockStateAddr, blockSize);
    }
    AddHWDescSequence(qid, &desc);
}

void StoreCipherState(int qid, DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t modeAddr          = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, mode);
    const DxSramAddr_t algAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, alg);
    const DxSramAddr_t directionAddr     = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, direction);
    const DxSramAddr_t blockStateAddr    = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, block_state);
    const DxSramAddr_t aesPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, reserved);
    const DxSramAddr_t isTunnelOpAddr    = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, isTunnelOp);
    const DxSramAddr_t tunnetDirAddr     = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, tunnetDir);
    const DxSramAddr_t engineCoreAddr    = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, engineCore);
    HwDesc_s desc;
    uint32_t block_size;

    if (ReadContextWord(modeAddr) == SEP_CIPHER_ECB) {
        return;
    }

    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, ReadContextWord(modeAddr));
    switch (ReadContextWord(modeAddr)) {
    case SEP_CIPHER_CTR:
    case SEP_CIPHER_OFB:
    case SEP_CIPHER_XTS:
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
        break;
    default:
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    }

    if (ReadContextWord(algAddr) == DRV_CRYPTO_ALG_AES) {
        block_size = SEP_AES_BLOCK_SIZE;
        if (ReadContextWord(isTunnelOpAddr) == 0) {
            HW_DESC_SET_CIPHER_CONFIG0(&desc, ReadContextWord(directionAddr));
        } else {
            HW_DESC_SET_CIPHER_CONFIG0(&desc, ReadContextWord(tunnetDirAddr));
        }
        HW_DESC_SET_CIPHER_CONFIG1(&desc, ReadContextWord(isTunnelOpAddr));

        if (ReadContextWord(engineCoreAddr) == SEP_AES_ENGINE2) {
            HW_DESC_SET_FLOW_MODE(&desc, S_AES2_to_DOUT);
        } else {
            HW_DESC_SET_FLOW_MODE(&desc, S_AES_to_DOUT);
        }
    } else {
        block_size = SASI_DRV_DES_IV_SIZE;
        HW_DESC_SET_CIPHER_CONFIG0(&desc, ReadContextWord(directionAddr));
        HW_DESC_SET_FLOW_MODE(&desc, S_DES_to_DOUT);
    }
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, blockStateAddr, block_size);

    AddHWDescSequence(qid, &desc);
}

void LoadCipherKey(int qid, DxSramAddr_t ctxAddr)
{
    HwDesc_s desc;
    const DxSramAddr_t keyAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key);
    const DxSramAddr_t modeAddr          = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, mode);
    const DxSramAddr_t algAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, alg);
    const DxSramAddr_t directionAddr     = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, direction);
    const DxSramAddr_t keySizeAddr       = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key_size);
    const DxSramAddr_t xexKeyAddr        = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, xex_key);
    const DxSramAddr_t dataUnitSizeAddr  = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, data_unit_size);
    const DxSramAddr_t cryptoKeyTypeAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, crypto_key_type);
    const DxSramAddr_t aesPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, reserved);
    const DxSramAddr_t isTunnelOpAddr    = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, isTunnelOp);
    const DxSramAddr_t tunnetDirAddr     = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, tunnetDir);
    const DxSramAddr_t engineCoreAddr    = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, engineCore);
    const DxSramAddr_t xcbcKeyK1         = keyAddr + SEP_AES_128_BIT_KEY_SIZE;
    const DxSramAddr_t xcbcKeyK2         = xcbcKeyK1 + SEP_AES_128_BIT_KEY_SIZE;
    const DxSramAddr_t xcbcKeyK3         = xcbcKeyK2 + SEP_AES_128_BIT_KEY_SIZE;
    const enum sep_crypto_direction encDecFlag = ReadContextWord(directionAddr);
    const enum drv_crypto_key_type aesKeyType  = ReadContextWord(cryptoKeyTypeAddr);
    uint32_t keySize                           = ReadContextWord(keySizeAddr);

    HW_DESC_INIT(&desc);

    /* key size 24 bytes count as 32 bytes, make sure to zero wise upper 8 bytes */
    if (keySize == 24) {
        keySize = SEP_AES_KEY_SIZE_MAX;
        ClearCtxField(keyAddr + 24, SEP_AES_KEY_SIZE_MAX - 24);
    }

    HW_DESC_SET_CIPHER_MODE(&desc, ReadContextWord(modeAddr));
    if (ReadContextWord(algAddr) == DRV_CRYPTO_ALG_AES) {
        if (ReadContextWord(isTunnelOpAddr) == 0) {
            HW_DESC_SET_CIPHER_CONFIG0(&desc, encDecFlag);
        } else {
            HW_DESC_SET_CIPHER_CONFIG0(&desc, ReadContextWord(tunnetDirAddr));
        }
        HW_DESC_SET_CIPHER_CONFIG1(&desc, ReadContextWord(isTunnelOpAddr));
        HW_DESC_SET_CIPHER_DO(&desc, aesKeyType);
        HW_DESC_SET_CIPHER_CONFIG2(&desc, aesKeyType);
        HW_DESC_SET_KEY_SIZE_AES(&desc, ReadContextWord(keySizeAddr));
        switch (ReadContextWord(modeAddr)) {
        case SEP_CIPHER_XCBC_MAC:
            HW_DESC_SET_STATE_DIN_PARAM(&desc, xcbcKeyK1, SEP_AES_128_BIT_KEY_SIZE);
            HW_DESC_SET_KEY_SIZE_AES(&desc, SEP_AES_128_BIT_KEY_SIZE);
            break;
        default:
            if (aesKeyType == DRV_USER_KEY) {
                HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, keySize);
            }
        }

        if (ReadContextWord(engineCoreAddr) == SEP_AES_ENGINE2) {
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES2);
        } else {
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
        }
    } else {
        HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, ReadContextWord(keySizeAddr));
        HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_DES);
        HW_DESC_SET_KEY_SIZE_DES(&desc, ReadContextWord(keySizeAddr));
        HW_DESC_SET_CIPHER_CONFIG0(&desc, encDecFlag);
    }
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(qid, &desc);

    if (ReadContextWord(modeAddr) == SEP_CIPHER_XTS) {
        HW_DESC_INIT(&desc);

        /* load XEX key */
        HW_DESC_SET_CIPHER_MODE(&desc, ReadContextWord(modeAddr));
        if (ReadContextWord(isTunnelOpAddr) == 0) {
            HW_DESC_SET_CIPHER_CONFIG0(&desc, encDecFlag);
        } else {
            HW_DESC_SET_CIPHER_CONFIG0(&desc, ReadContextWord(tunnetDirAddr));
        }
        HW_DESC_SET_STATE_DIN_PARAM(&desc, xexKeyAddr, keySize);
        HW_DESC_SET_XEX_DATA_UNIT_SIZE(&desc, ReadContextWord(dataUnitSizeAddr));
        HW_DESC_SET_CIPHER_CONFIG1(&desc, ReadContextWord(isTunnelOpAddr));
        if (ReadContextWord(engineCoreAddr) == SEP_AES_ENGINE2) {
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES2);
        } else {
            HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
        }
        HW_DESC_SET_KEY_SIZE_AES(&desc, keySize);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_XEX_KEY);
        AddHWDescSequence(qid, &desc);
    }

    if (ReadContextWord(modeAddr) == SEP_CIPHER_XCBC_MAC) {
        /* load K2 key */
        /* NO init - reuse previous descriptor settings */
        HW_DESC_SET_STATE_DIN_PARAM(&desc, xcbcKeyK2, SEP_AES_128_BIT_KEY_SIZE);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
        AddHWDescSequence(qid, &desc);

        /* load K3 key */
        /* NO init - reuse previous descriptor settings */
        HW_DESC_SET_STATE_DIN_PARAM(&desc, xcbcKeyK3, SEP_AES_128_BIT_KEY_SIZE);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE2);
        AddHWDescSequence(qid, &desc);
    }
}

/* !
 * Revert operation of the last MAC block processing
 * This function is used for AES-XCBC-MAC and AES-CMAC when finalize
 * has not data. It reverts the last block operation in order to allow
 * redoing it as final.
 *
 * \param qid
 * \param pCtx
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
static int RevertLastMacBlock(int qid, DxSramAddr_t ctxAddr)
{
    HwDesc_s desc;
    const DxSramAddr_t keyAddr                = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key);
    const DxSramAddr_t modeAddr               = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, mode);
    const DxSramAddr_t blockStateAddr         = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, block_state);
    const DxSramAddr_t keySizeAddr            = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key_size);
    const DxSramAddr_t cryptoKeyTypeAddr      = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, crypto_key_type);
    const DxSramAddr_t xcbcKeyK1              = keyAddr + SEP_AES_128_BIT_KEY_SIZE;
    const enum drv_crypto_key_type aesKeyType = ReadContextWord(cryptoKeyTypeAddr);
    uint32_t keySize                          = ReadContextWord(keySizeAddr);

    /* Relevant only for AES-CMAC and AES-XCBC-MAC */
    if ((ReadContextWord(modeAddr) != SEP_CIPHER_XCBC_MAC) && (ReadContextWord(modeAddr) != SEP_CIPHER_CMAC)) {
        SASI_PAL_LOG_ERR("Wrong mode for this function (mode %d)\n", ReadContextWord(modeAddr));
        return SASI_RET_UNSUPP_ALG_MODE;
    }
    if (ReadContextWord(cryptoKeyTypeAddr) == DRV_ROOT_KEY) {
        SASI_PAL_LOG_ERR("RKEK not allowed for XCBC-MAC/CMAC\n");
        return SASI_RET_UNSUPP_ALG_MODE;
    }
    /* CMAC and XCBC must use 128b keys */
    if ((ReadContextWord(modeAddr) == SEP_CIPHER_XCBC_MAC) &&
        (ReadContextWord(keySizeAddr) != SEP_AES_128_BIT_KEY_SIZE)) {
        SASI_PAL_LOG_ERR("Bad key for XCBC-MAC %x\n", (unsigned int)ReadContextWord(keySizeAddr));
        return SASI_RET_INVARG_KEY_SIZE;
    }

    /* Load key for ECB decryption */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, SEP_CIPHER_ECB);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, SEP_CRYPTO_DIRECTION_DECRYPT);
    HW_DESC_SET_CIPHER_DO(&desc, aesKeyType);
    HW_DESC_SET_CIPHER_CONFIG2(&desc, aesKeyType);

    if (ReadContextWord(modeAddr) == SEP_CIPHER_XCBC_MAC) { /* XCBC K1 key is used (always 128b) */
        HW_DESC_SET_STATE_DIN_PARAM(&desc, xcbcKeyK1, SEP_AES_128_BIT_KEY_SIZE);
        HW_DESC_SET_KEY_SIZE_AES(&desc, SEP_AES_128_BIT_KEY_SIZE);
    } else { /* CMAC */
        HW_DESC_SET_KEY_SIZE_AES(&desc, ReadContextWord(keySizeAddr));
        if (aesKeyType == DRV_USER_KEY) {
            HW_DESC_SET_STATE_DIN_PARAM(&desc, keyAddr, keySize);
        }
    }
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(qid, &desc);

    /* Initiate decryption of block state to previous block_state-XOR-M[n] */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, blockStateAddr, SEP_AES_BLOCK_SIZE);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, blockStateAddr, SEP_AES_BLOCK_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
    AddHWDescSequence(qid, &desc);

    return SASI_RET_OK;
}

static void CalcXcbcKeys(int qid, DxSramAddr_t ctxAddr)
{
    int i;
    HwDesc_s setup_desc, data_desc;

    const DxSramAddr_t cryptoKeyTypeAddr      = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, crypto_key_type);
    const enum drv_crypto_key_type aesKeyType = ReadContextWord(cryptoKeyTypeAddr);

    /* Overload key+xex_key fields with Xcbc keys */
    const DxSramAddr_t keyAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key);
    DxSramAddr_t derivedKey    = keyAddr + SEP_AES_128_BIT_KEY_SIZE;
    uint32_t constKey          = 0x01010101;

    /* Prepare key setup descriptor (same for all XCBC-MAC keys) */
    HW_DESC_INIT(&setup_desc);
    HW_DESC_SET_CIPHER_MODE(&setup_desc, SEP_CIPHER_ECB);
    HW_DESC_SET_CIPHER_CONFIG0(&setup_desc, SEP_CRYPTO_DIRECTION_ENCRYPT);
    HW_DESC_SET_KEY_SIZE_AES(&setup_desc, SEP_AES_128_BIT_KEY_SIZE);
    HW_DESC_SET_FLOW_MODE(&setup_desc, S_DIN_to_AES);
    HW_DESC_SET_SETUP_MODE(&setup_desc, SETUP_LOAD_KEY0);

    /* subkeys are derived according to keytype (user, hw) */
    HW_DESC_SET_CIPHER_DO(&setup_desc, aesKeyType);
    HW_DESC_SET_CIPHER_CONFIG2(&setup_desc, aesKeyType);
    if (aesKeyType == DRV_USER_KEY) {
        HW_DESC_SET_STATE_DIN_PARAM(&setup_desc, keyAddr, SEP_AES_128_BIT_KEY_SIZE);
    }

    /* load user key */
    AddHWDescSequence(qid, &setup_desc);

    HW_DESC_INIT(&data_desc);
    HW_DESC_SET_FLOW_MODE(&data_desc, DIN_AES_DOUT);

    for (i = 0; i < AES_XCBC_MAC_NUM_KEYS; i++) {
        /* encrypt each XCBC constant with the user given key to get K1, K2, K3 */
        HW_DESC_SET_DIN_CONST(&data_desc, (constKey * (i + 1)), SEP_AES_128_BIT_KEY_SIZE);
        HW_DESC_SET_STATE_DOUT_PARAM(&data_desc, derivedKey, SEP_AES_128_BIT_KEY_SIZE);
        AddHWDescSequence(qid, &data_desc);
        /* Procede to next derived key calculation */
        derivedKey += SEP_AES_128_BIT_KEY_SIZE;
    }

    /* All subkeys are loaded as user keys */
    WriteContextWord(cryptoKeyTypeAddr, DRV_USER_KEY);
}

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

/* !
 * This function is used to initialize the AES machine to perform the AES
 * operations. This should be the first function called.
 *
 * \param pCtx A pointer to the context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int InitCipher(DxSramAddr_t ctxAddr)
{
    const DxSramAddr_t modeAddr          = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, mode);
    const DxSramAddr_t algAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, alg);
    const DxSramAddr_t keyAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key);
    const DxSramAddr_t keySizeAddr       = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key_size);
    const DxSramAddr_t blockStateAddr    = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, block_state);
    const DxSramAddr_t cryptoKeyTypeAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, crypto_key_type);
    const DxSramAddr_t aesPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, reserved);
    const DxSramAddr_t isTunnelOpAddr    = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, isTunnelOp);
    const DxSramAddr_t engineCoreAddr    = GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, engineCore);
    const DxSramAddr_t dataBlockTypeAddr =
        GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, dataBlockType);
    int qid = CURR_QUEUE_ID(); /* qid is stored in pxTaskTag field */

    if (ReadContextWord(algAddr) == DRV_CRYPTO_ALG_DES) {
        /* in caes of double DES k1 = K3, copy k1-> K3 */
        if (ReadContextWord(keySizeAddr) == SASI_DRV_DES_DOUBLE_KEY_SIZE) {
#ifdef DX_CC_SRAM_INDIRECT_ACCESS
            /* temporary buffer to allow key coping, must be aligned to words */
            uint32_t tKeybuff[SASI_DRV_DES_ONE_KEY_SIZE / sizeof(uint32_t)];
            ReadContextField(keyAddr, tKeybuff, SASI_DRV_DES_ONE_KEY_SIZE);
            WriteContextField((keyAddr + SASI_DRV_DES_DOUBLE_KEY_SIZE), tKeybuff, SASI_DRV_DES_ONE_KEY_SIZE);
            WriteContextWord(keySizeAddr, SASI_DRV_DES_TRIPLE_KEY_SIZE);
#else
            SaSi_PalMemCopy((keyAddr + SASI_DRV_DES_DOUBLE_KEY_SIZE), keyAddr, SASI_DRV_DES_ONE_KEY_SIZE);
            keySizeAddr = SASI_DRV_DES_TRIPLE_KEY_SIZE;
#endif
        }
        return SASI_RET_OK;
    }

    switch (ReadContextWord(modeAddr)) {
    case SEP_CIPHER_CMAC:
        ClearCtxField(blockStateAddr, SEP_AES_BLOCK_SIZE);
        if (ReadContextWord(cryptoKeyTypeAddr) == DRV_ROOT_KEY) {
            uint32_t keySize;
            GET_ROOT_KEY_SIZE(keySize);
            WriteContextWord(keySizeAddr, keySize);
        }
        break;
    case SEP_CIPHER_XCBC_MAC:
        if (ReadContextWord(keySizeAddr) != SEP_AES_128_BIT_KEY_SIZE) {
            SASI_PAL_LOG_ERR("Invalid key size\n");
            return SASI_RET_INVARG;
        }
        ClearCtxField(blockStateAddr, SEP_AES_BLOCK_SIZE);
        CalcXcbcKeys(qid, ctxAddr);
        break;
    default:
        break;
    }

    /* init private context */
    WriteContextWord(engineCoreAddr, SEP_AES_ENGINE1);
    WriteContextWord(isTunnelOpAddr, TUNNEL_OFF);
    WriteContextWord(dataBlockTypeAddr, FIRST_BLOCK);

    return SASI_RET_OK;
}

/* !
 * This function is used to process block(s) of data using the AES machine.
 *
 * \param pCtx A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int ProcessCipher(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    SaSiDmaAddr_t pInputData = 0, pOutputData = 0;
    uint32_t DataInSize = 0, DataOutSize = 0;
    uint32_t isNotLastDescriptor = 0;
    uint32_t flowMode;
    HwDesc_s desc;
    DmaMode_t dmaInMode                  = NO_DMA;
    DmaMode_t dmaOutMode                 = NO_DMA;
    uint8_t inAxiNs                      = pDmaInputBuffer->axiNs;
    uint8_t outAxiNs                     = pDmaOutputBuffer->axiNs;
    int qid                              = CURR_QUEUE_ID();
    int drvRc                            = SASI_RET_OK;
    const DxSramAddr_t modeAddr          = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, mode);
    const DxSramAddr_t algAddr           = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, alg);
    const DxSramAddr_t aesPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, reserved);
    const DxSramAddr_t dataBlockTypeAddr =
        GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, dataBlockType);
    const int isInplaceOp =
        (((pDmaInputBuffer->pData == pDmaOutputBuffer->pData) &&
          (pDmaInputBuffer->dmaBufType == pDmaOutputBuffer->dmaBufType)) ||
         (ReadContextWord(modeAddr) == SEP_CIPHER_CBC_MAC) || (ReadContextWord(modeAddr) == SEP_CIPHER_XCBC_MAC) ||
         (ReadContextWord(modeAddr) == SEP_CIPHER_CMAC));

    if (ReadContextWord(modeAddr) == SEP_CIPHER_CBC_CTS && ReadContextWord(dataBlockTypeAddr) != LAST_BLOCK) {
        WriteContextWord(modeAddr, SEP_CIPHER_CBC);
        LoadCipherKey(qid, ctxAddr);
        LoadCipherState(qid, ctxAddr, 0);
        WriteContextWord(modeAddr, SEP_CIPHER_CBC_CTS);
    } else {
        LoadCipherKey(qid, ctxAddr);
        LoadCipherState(qid, ctxAddr, 0);
    }

    /* set the input/output pointers according to the DMA mode */
    dmaInMode  = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);
    dmaOutMode = DMA_BUF_TYPE_TO_MODE(pDmaOutputBuffer->dmaBufType);

    if ((!isInplaceOp) &&
        (((dmaInMode == NO_DMA) && (dmaOutMode != NO_DMA)) || ((dmaOutMode == NO_DMA) && (dmaInMode != NO_DMA)))) {
        SASI_PAL_LOG_ERR("Inconsistent DMA mode for in/out buffers");
        drvRc = SASI_RET_INVARG;
        goto EndWithErr;
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
    case NO_DMA:
        pInputData = 0;
        /* data size is meaningless in DMA-MLLI mode */
        DataInSize = 0;
        break;
    default:
        SASI_PAL_LOG_ERR("Invalid DMA Input mode\n");
        drvRc = SASI_RET_INVARG;
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
        case NO_DMA:
            pOutputData = 0;
            /* data size is meaningless in DMA-MLLI mode */
            DataOutSize = 0;
            break;
        default:
            SASI_PAL_LOG_ERR("Invalid DMA Output mode\n");
            drvRc = SASI_RET_INVARG;
            goto EndWithErr;
        }
    }

    if ((ReadContextWord(modeAddr) == SEP_CIPHER_CMAC) || (ReadContextWord(modeAddr) == SEP_CIPHER_XCBC_MAC)) {
        isNotLastDescriptor = 1;
    }

    /* process the AES flow */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_TYPE(&desc, dmaInMode, pInputData, DataInSize, QID_TO_AXI_ID(qid), inAxiNs);
    if (isNotLastDescriptor) {
        HW_DESC_SET_DIN_NOT_LAST_INDICATION(&desc);
    }

    switch (ReadContextWord(modeAddr)) {
    case SEP_CIPHER_CBC_MAC:
    case SEP_CIPHER_CMAC:
    case SEP_CIPHER_XCBC_MAC:
        break;
    default:
        HW_DESC_SET_DOUT_TYPE(&desc, dmaOutMode, pOutputData, DataOutSize, QID_TO_AXI_ID(qid), outAxiNs);
    }

    flowMode = (ReadContextWord(algAddr) == DRV_CRYPTO_ALG_AES) ? DIN_AES_DOUT : DIN_DES_DOUT;

    HW_DESC_SET_FLOW_MODE(&desc, flowMode);

#ifdef SEP_PERFORMANCE_TEST
    /* For testing exact HW time */
    HW_QUEUE_WAIT_UNTIL_EMPTY(qid);
    TIMING_MARK(1);
    TIMING_MARK(2);
#endif
    AddHWDescSequence(qid, &desc);

#ifdef SEP_PERFORMANCE_TEST
    TIMING_MARK(2);
    HW_QUEUE_WAIT_UNTIL_EMPTY(qid);
    TIMING_MARK(1);
#endif

    /* at least one block of data processed */
    WriteContextWord(dataBlockTypeAddr, MIDDLE_BLOCK);

    /* get machine state */
    StoreCipherState(qid, ctxAddr);

EndWithErr:
    return drvRc;
}

/* !
 * This function is used as finish operation of AES on XCBC, CMAC, CBC
 * and other modes besides XTS mode.
 * The function may either be called after "InitCipher" or "ProcessCipher".
 *
 * \param pCtx A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int FinalizeCipher(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    const DxSramAddr_t modeAddr          = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, mode);
    const DxSramAddr_t keySizeAddr       = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, key_size);
    const DxSramAddr_t aesPrivateCtxAddr = GET_CTX_FIELD_ADDR(ctxAddr, struct drv_ctx_cipher, reserved);
    const DxSramAddr_t dataBlockTypeAddr =
        GET_CTX_FIELD_ADDR(aesPrivateCtxAddr, SepCipherPrivateContext_s, dataBlockType);
    uint32_t isRemainingData = 0;
    uint32_t DataInSize      = 0;
    SaSiDmaAddr_t pInputData = 0;
    HwDesc_s desc;
    DmaMode_t dmaMode = NO_DMA;
    uint8_t inAxiNs   = pDmaInputBuffer->axiNs;
    int qid           = CURR_QUEUE_ID();
    int drvRc         = SASI_RET_OK;

    HW_DESC_INIT(&desc);

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
        SASI_PAL_LOG_ERR("Invalid DMA mode\n");
        drvRc = SASI_RET_INVARG;
        goto EndWithErr;
    }

    switch (ReadContextWord(modeAddr)) {
    case SEP_CIPHER_CMAC:
    case SEP_CIPHER_XCBC_MAC: {
        if (isRemainingData == 1) {
            if (dmaMode == DMA_MLLI) {
                PrepareMLLITable(qid, pDmaInputBuffer->pData, pDmaInputBuffer->size, pDmaInputBuffer->axiNs,
                                 MLLI_INPUT_TABLE);
                pInputData = GetFirstLliPtr(qid, MLLI_INPUT_TABLE);
                /* data size should hold the number of LLIs */
                DataInSize = (pDmaInputBuffer->size) / LLI_ENTRY_BYTE_SIZE - 1; // reduce dummy entry (tail)
            } else {
                pInputData = pDmaInputBuffer->pData;
                DataInSize = pDmaInputBuffer->size;
            }
        }

        /* Prepare processing descriptor to be pushed after loading state+key */
        HW_DESC_INIT(&desc);
        if (isRemainingData == 0) {
            if (ReadContextWord(dataBlockTypeAddr) == FIRST_BLOCK) {
                /* MAC for 0 bytes */
                HW_DESC_SET_CIPHER_MODE(&desc, ReadContextWord(modeAddr));
                HW_DESC_SET_KEY_SIZE_AES(&desc, ReadContextWord(keySizeAddr));
                HW_DESC_SET_CMAC_SIZE0_MODE(&desc);
                HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
            } else {
                /* final with 0 data but MAC total data size > 0 */
                drvRc = RevertLastMacBlock(qid, ctxAddr); /* Get C[n-1]-xor-M[n] */
                if (drvRc != SASI_RET_OK) {
                    goto EndWithErr;
                }
                /* Finish with data==0 is identical to "final"
                   op. on the last (prev.) block (XOR with 0) */
                HW_DESC_SET_DIN_CONST(&desc, 0, SEP_AES_BLOCK_SIZE);
                HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
            }
        } else {
            HW_DESC_SET_DIN_TYPE(&desc, dmaMode, pInputData, DataInSize, QID_TO_AXI_ID(qid), inAxiNs);
            HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
        }

        /* load AES key and iv length and digest */
        LoadCipherKey(qid, ctxAddr);
        LoadCipherState(qid, ctxAddr, 0);
        /* Process last block */

        AddHWDescSequence(qid, &desc);

        /* get machine state */
        StoreCipherState(qid, ctxAddr);
        break;
    }
    case SEP_CIPHER_CBC_CTS: {
        /* In case of data size = SEP_AES_BLOCK_SIZE check that no blocks were processed before */
        if ((pDmaInputBuffer->size == SEP_AES_BLOCK_SIZE) && (ReadContextWord(dataBlockTypeAddr) == MIDDLE_BLOCK)) {
            SASI_PAL_LOG_ERR("Invalid dataIn size\n");
            drvRc = SASI_RET_INVARG;
            goto EndWithErr;
        }
        /* Call ProcessCTSFinalizeCipher to process AES CTS finalize operation */
        WriteContextWord(dataBlockTypeAddr, LAST_BLOCK);
    }
    default:
        if (isRemainingData) {
            /* process all tables and get state from the AES machine */
            drvRc = ProcessCipher(ctxAddr, pDmaInputBuffer, pDmaOutputBuffer);
            if (drvRc != SASI_RET_OK) {
                goto EndWithErr;
            }
        } else if (ReadContextWord(modeAddr) == SEP_CIPHER_CBC_MAC) {
            /* in-case ZERO data has processed the output would be the encrypted IV */
            if (ReadContextWord(dataBlockTypeAddr) == FIRST_BLOCK) {
                /* load AES key and iv length and digest */
                LoadCipherKey(qid, ctxAddr);
                LoadCipherState(qid, ctxAddr, 0);
                HW_DESC_INIT(&desc);
                HW_DESC_SET_DIN_CONST(&desc, 0, SEP_AES_BLOCK_SIZE);

                HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
                AddHWDescSequence(qid, &desc);
                /* get mac result */
                StoreCipherState(qid, ctxAddr);
            }
        }
    }

EndWithErr:
    return drvRc;
}
