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
#include "dx_util.h"
#include "dx_util_rpmb.h"
#include "dx_util_defs.h"
#include "dx_error.h"
#include "crys_hmac.h"
#include "dx_pal_mutex.h"
#include "sym_adaptor_driver.h"
#include "sym_adaptor_driver_int.h"

/* *********************** Defines **************************** */
#define CRYS_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS ((CRYS_HMAC_USER_CTX_SIZE_IN_WORDS - 3) / 2)
typedef struct CRYS_HMACPrivateContext_t {
    uint32_t isLastBlockProcessed;
} CRYS_HMACPrivateContext_t;

/* label "RPMB KEY", length 0x100 */
#define KEY_DERIVATION_4_RPMB 0x01, 0x52, 0x50, 0x4D, 0x42, 0x20, 0x4B, 0x45, 0x59, 0x00, 0x01, 0x00

/* To perform hash update, we join 64 data frames together to one chunk (284*64).
   Hence, in case of un-contiguous frames, there will be up to 128 MLLI entries */
#define RPMB_MAX_BLOCKS_PER_UPDATE 64
#define RPMB_MAX_PAGES_PER_BLOCK   2

typedef struct {
    uint32_t numOfBlocks[RPMB_MAX_BLOCKS_PER_UPDATE];
    DX_PAL_DmaBlockInfo_t pBlockEntry[RPMB_MAX_PAGES_PER_BLOCK];
} RpmbDmaBuffBlocksInfo_t;

typedef struct {
    mlliTable_t devBuffer;
    RpmbDmaBuffBlocksInfo_t blocksList;
    DX_PAL_DmaBufferHandle buffMainH[RPMB_MAX_BLOCKS_PER_UPDATE];
    DX_PAL_DmaBufferHandle buffMlliH;
} RpmbDmaBuildBuffer_t;

/* *********************** Extern variables ******************* */
extern DX_PAL_MUTEX dxSymCryptoMutex;

/* ***************************************************************
 *                          RPMB internal functions
 * ************************************************************** */

int RpmbSymDriverAdaptorModuleInit(void);

int RpmbSymDriverAdaptorModuleTerminate(void);

DxError_t RpmbHmacUpdate(CRYS_HMACUserContext_t *ContextID_ptr, unsigned long *pListOfDataFrames, uint32_t listSize);

DxError_t RpmbHmacFinish(CRYS_HMACUserContext_t *ContextID_ptr, CRYS_HASH_Result_t HmacResultBuff);

int RpmbSymDriverAdaptorProcess(struct sep_ctx_generic *pCtx, unsigned long *pListOfDataFrames, uint32_t listSize);

int RpmbSymDriverAdaptorFinalize(struct sep_ctx_generic *pCtx, unsigned long *pListOfDataFrames, uint32_t listSize);

int RpmbSymAdaptor2CrysHmacErr(int symRetCode, uint32_t errorInfo);

uint32_t RpmbBuildDmaFromDataPtr(unsigned long *pListOfDataFrames, uint32_t listSize,
                                 DX_PAL_DmaBufferDirection_t direction, DmaBuffer_s *pDmaBuff,
                                 RpmbDmaBuildBuffer_t *pInterBuildBuff);

uint32_t RpmbBuildDataPtrFromDma(unsigned long *pListOfDataFrames, uint32_t listSize,
                                 DX_PAL_DmaBufferDirection_t direction, DmaBuffer_s *pDmaBuff,
                                 RpmbDmaBuildBuffer_t *pInterBuildBuff);

uint32_t RpmbAllocDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff);

void RpmbClearDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff);

void RpmbFreeDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff);
