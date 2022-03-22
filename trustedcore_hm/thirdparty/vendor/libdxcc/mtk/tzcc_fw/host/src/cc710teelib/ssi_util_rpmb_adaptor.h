/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "ssi_util.h"
#include "ssi_util_rpmb.h"
#include "ssi_util_int_defs.h"
#include "ssi_error.h"
#include "sasi_hmac.h"
#include "ssi_pal_mutex.h"
#include "sym_adaptor_driver.h"
#include "sym_adaptor_driver_int.h"

/* *********************** Defines **************************** */
#define SaSi_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS ((SaSi_HMAC_USER_CTX_SIZE_IN_WORDS - 3) / 2)
typedef struct SaSi_HMACPrivateContext_t {
    uint32_t isLastBlockProcessed;
} SaSi_HMACPrivateContext_t;

#define RPMB_KEY_DERIVATION_LABAL   0x52, 0x50, 0x4D, 0x42, 0x20, 0x4B, 0x45, 0x59
#define RPMB_KEY_DERIVATION_CONTEXT 0x53, 0x41, 0x53, 0x49

/* To perform hash update, we join 64 data frames together to one chunk (284*64).
   Hence, in case of un-contiguous frames, there is up to 128 MLLI entries */
#define RPMB_MAX_BLOCKS_PER_UPDATE 64
#define RPMB_MAX_PAGES_PER_BLOCK   2

typedef struct {
    uint32_t numOfBlocks[RPMB_MAX_BLOCKS_PER_UPDATE];
    SaSi_PalDmaBlockInfo_t pBlockEntry[RPMB_MAX_PAGES_PER_BLOCK];
} RpmbDmaBuffBlocksInfo_t;

typedef struct {
    mlliTable_t devBuffer;
    RpmbDmaBuffBlocksInfo_t blocksList;
    SaSi_PalDmaBufferHandle buffMainH[RPMB_MAX_BLOCKS_PER_UPDATE];
    SaSi_PalDmaBufferHandle buffMlliH;
} RpmbDmaBuildBuffer_t;

/* *********************** Extern variables ******************* */
extern SaSi_PalMutex sasiSymCryptoMutex;

/* ***************************************************************
 *                          RPMB internal functions
 * ************************************************************** */

int RpmbSymDriverAdaptorModuleInit(void);

int RpmbSymDriverAdaptorModuleTerminate(void);

SaSiError_t RpmbHmacUpdate(SaSi_HMACUserContext_t *ContextID_ptr, unsigned long *pListOfDataFrames, uint32_t listSize);

SaSiError_t RpmbHmacFinish(SaSi_HMACUserContext_t *ContextID_ptr, SaSi_HASH_Result_t HmacResultBuff);

int RpmbSymDriverAdaptorProcess(struct drv_ctx_generic *pCtx, unsigned long *pListOfDataFrames, uint32_t listSize);

int RpmbSymDriverAdaptorFinalize(struct drv_ctx_generic *pCtx, unsigned long *pListOfDataFrames, uint32_t listSize);

int RpmbSymAdaptor2SasiHmacErr(int symRetCode, uint32_t errorInfo);

uint32_t RpmbBuildDmaFromDataPtr(unsigned long *pListOfDataFrames, uint32_t listSize,
                                 SaSi_PalDmaBufferDirection_t direction, DmaBuffer_s *pDmaBuff,
                                 RpmbDmaBuildBuffer_t *pInterBuildBuff);

uint32_t RpmbBuildDataPtrFromDma(unsigned long *pListOfDataFrames, uint32_t listSize,
                                 SaSi_PalDmaBufferDirection_t direction, RpmbDmaBuildBuffer_t *pInterBuildBuff);

uint32_t RpmbAllocDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff);

void RpmbClearDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff);

void RpmbFreeDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff);
