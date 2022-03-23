/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

/* .............. SaSi level includes ................. */

#include "ssi_pal_mem.h"
#include "sasi.h"
#include "sasi_common_error.h"
#include "PLAT_SystemDep.h"

/* .............. LLF level includes .................. */

/* *********************** Defines **************************** */

/* *********************** MACROS **************************** */

/* *********************** Global Data **************************** */

/* ************ Private function prototype ************** */

/* *********************** Public Functions **************************** */

/* *********************************************************************************************************** */
/*
 * @brief The SaSi_COMMON_CutAndSaveEndOfLliData() function saves the data from end of source
 *        memory, pointed by LLI table, to destination memory, and decreases the LLI table accordingly.
 *
 *        The function executes the following major steps:
 *
 *        1. Starts copy bytes from last byte of last chunck of source LLI table into
 *           last byte of destination memory.
 *        2. Continues copy bytes in reverse order while not completes copying of all amount of data.
 *        3. If last chunck of source or destination data is not enough, the function crosses
 *           to next chunck of LLI table.
 *        4. Decreases the Data size of last updated LLI entry and sets the LAST bit.
 *        5. Exits with the OK code.
 *
 *
 * @param[in] SrcLliTab_ptr - The pointer to the LLI table, containing pointers and sizes of
 *                            chuncks of source data. The table need to be aligned and placed
 *                            in SRAM.
 * @param[in/out] SrcLliTabSize_ptr -   The pointer to buffer, containing th size of the LLI table in words.
 * @param[in] Dest_ptr  -  The destination address for copying the data.
 * @param[in] DataSize  -  The count of bytes to copy.
 *
 * @return SaSiError_t - On success SaSi_OK is returned,
 *                     - SaSi_COMMON_ERROR_IN_SAVING_LLI_DATA_ERROR
 *
 * NOTE: 1. Because the function is intended for internal using, it is presumed that all input parameters
 *          are valid.
 *       2. Assumed, that copied source not may to take more than two last chuncks of source memory.
 */
SaSiError_t SaSi_COMMON_CutAndSaveEndOfLliData(uint32_t *SrcLliTab_ptr, uint32_t *SrcLliTabSize_ptr, uint8_t *Dst_ptr,
                                               uint32_t DataSize)
{
    /* FUNCTION DECLARATIONS */

    /* the return error identifier */
    SaSiError_t Error;

    /* loop variables */
    uint32_t NumBytesCopied;

    /* source address pointer */
    uint8_t *Src_ptr = NULL;

    /* curent LLI memory chunck word number and size of currently used chuncks */
    int32_t ChunckNum;
    uint32_t ChunckSize, UsedChuncksSize;
    uint32_t RemainingDataSize;

    /* host base addr workaround */
    uint32_t HostBaseAddr = 0x0;
    /* FUNCTION LOGIC */

    /* ............... local initializations .............................. */
    /* -------------------------------------------------------------------- */

    /* initializing the Error to O.K */
    Error = SaSi_OK;

#ifdef SaSi_SEP_SIDE_WORK_MODE

    SaSi_PLAT_SYS_ReadRegister(0x400091dc, HostBaseAddr);

    HostBaseAddr = (HostBaseAddr << 16);
#endif /* SaSi_SEP_SIDE_WORK_MODE */

    /* set chunck number to last chunck address word */
    ChunckNum = *SrcLliTabSize_ptr;

    NumBytesCopied = 0;

    /* initialize chunck size according to last chunck of memory */
    UsedChuncksSize = 0;

    /* set destination address to last byte to copy */
    Dst_ptr = Dst_ptr + DataSize - 1;

    /* size of data remained to copy */
    RemainingDataSize = DataSize;

    /* copying loop */
    while (NumBytesCopied < DataSize) {
        if (NumBytesCopied == 0 || NumBytesCopied == UsedChuncksSize) {
            /* set the current chunck */
            ChunckNum = ChunckNum - 2;

            if (ChunckNum < 0)
                return SaSi_COMMON_ERROR_IN_SAVING_LLI_DATA_ERROR;

            /* current chunck size */
            ChunckSize = SrcLliTab_ptr[ChunckNum + 1];

            /* the size of the all used chuncks  */
            UsedChuncksSize = UsedChuncksSize + ChunckSize;

            /* set source start address to last byte of the chunck of memory */
            Src_ptr = (uint8_t *)SrcLliTab_ptr[ChunckNum] + ChunckSize - 1;
            /* calculate the corrext direct acccess address - in sep it with offset and in host it is zero */
            Src_ptr = Src_ptr - HostBaseAddr;

            /* if remaining DataSize < LLI entry size, then decrease the entry size ,
               else delete LLI entry  */
            if (RemainingDataSize < SrcLliTab_ptr[ChunckNum + 1])

                SrcLliTab_ptr[ChunckNum + 1] -= RemainingDataSize;

            else if (*SrcLliTabSize_ptr >= 2) /* delete LLI entry by decreasing the LLI table size */

                *SrcLliTabSize_ptr -= 2;

            else
                return SaSi_COMMON_ERROR_IN_SAVING_LLI_DATA_ERROR;
        }

        /* copy current byte */
        *Dst_ptr = *Src_ptr;

        /* decrment remaining data size and increment number of copied bytes */
        RemainingDataSize--;
        NumBytesCopied++;

        /* decrement pointers  */
        Dst_ptr--;
        Src_ptr--;
    }

    return Error;

} /* END OF SaSi_COMMON_CutAndSaveEndOfLliData */

/* *********************************************************************************************************** */
/*
 * @brief The SaSi_COMMON_CutAndSaveBeginOfLliData() function saves the data from beginning of source
 *        memory, pointed by LLI table, to destination memory, and decreases the LLI table accordingly.
 *
 *        The function executes the following major steps:
 *
 *        1. Starts copy bytes from first byte of first chunck of source LLI table into
 *           destination memory.
 *        2. If first chunck of source is not enough, the function crosses
 *           to next chunck of LLI table.
 *        3. Updates LLI table pointer and size according to copied amount of data.
 *        5. Exits with the OK code.
 *
 * @param[in/out] SrcLliTab_ptr_ptr - The pointer to pointer to the LLI table, containing pointers and
 *                            sizes of the chuncks of source data. The table need to be aligned and
 *                            placed in SRAM.
 * @param[in/out] SrcLliTabSize_ptr -   The pointer to buffer, containing th size of the LLI table in words.
 * @param[in] Dest_ptr  -  The destination address for copying the data.
 * @param[in] DataSize  -  The count of bytes to copy.
 *
 * @return - no return value.
 *
 * NOTE: 1. Because the function is intended for internal using, it is presumed that all input parameters
 *          are valid.
 *       2. Assumed, that copied source not may to take more than two first chuncks of source memory.
 */
void SaSi_COMMON_CutAndSaveBeginOfLliData(uint32_t **SrcLliTab_ptr_ptr, uint32_t *SrcLliTabSize_ptr, uint8_t *Dst_ptr,
                                          uint32_t DataSize)
{
    /* FUNCTION DECLARATIONS */

    /* number bytes copied */
    uint32_t NumBytesCopied;

    /* remainig data size */
    uint32_t RemainingDataSize;

    /* pointer to LLI table */
    uint32_t *SrcLliTab_ptr;

    /* pointer to source data */
    uint8_t *Src_ptr;

    /* host base addr workaround */
    uint32_t HostBaseAddr = 0x0;

    /* FUNCTION LOGIC */

    /* ............... local initializations .............................. */
    /* -------------------------------------------------------------------- */

#ifdef SaSi_SEP_SIDE_WORK_MODE

    SaSi_PLAT_SYS_ReadRegister(0x400091dc, HostBaseAddr);

    HostBaseAddr = (HostBaseAddr << 16);
#endif /* SaSi_SEP_SIDE_WORK_MODE */

    NumBytesCopied = 0; /* for preventing compiler warning */

    RemainingDataSize = 0; /* for preventing compiler warning */
                           /* pointer to LLI table */
    SrcLliTab_ptr = *SrcLliTab_ptr_ptr;

    /* if first LLI chunk of data is enough large, copy DataSize bytes,
       from first LLI chunk and update LLI table */
    if (DataSize < SrcLliTab_ptr[1]) {
        Src_ptr = (uint8_t *)(SrcLliTab_ptr[0] - HostBaseAddr);

        /* copy the data */
        SaSi_PalMemCopy(Dst_ptr, Src_ptr, DataSize);

        /* update LLI table */
        SrcLliTab_ptr[0] += DataSize;
        SrcLliTab_ptr[1] -= DataSize;

        /* set remining size of data to copy to 0 */
        RemainingDataSize = 0;
    }

    else if (DataSize >= SrcLliTab_ptr[1]) {
        Src_ptr = (uint8_t *)(SrcLliTab_ptr[0] - HostBaseAddr);

        /* copy all data from the first LLI chunk */
        SaSi_PalMemCopy(Dst_ptr, (uint8_t *)Src_ptr, SrcLliTab_ptr[1]);

        /* number of copied bytes */
        NumBytesCopied = SrcLliTab_ptr[1];

        /* calculate remining size of data to copy */
        RemainingDataSize = DataSize - NumBytesCopied;

        /* delete first LLI chunk by updating the LLI table pointer and size */
        SrcLliTab_ptr += 2;
        *SrcLliTabSize_ptr -= 2;
    }

    /* if not all needed data is copied, than copy remaining data from the next LLI chunk */
    if (RemainingDataSize > 0) {
        Src_ptr = (uint8_t *)(SrcLliTab_ptr[0] - HostBaseAddr);

        /* copy the remining data (note: the LLI table pointer is updated) */
        SaSi_PalMemCopy(Dst_ptr + NumBytesCopied, (uint8_t *)Src_ptr, RemainingDataSize);

        /* update the LLI chunck pointer and size */
        SrcLliTab_ptr[0] += RemainingDataSize;
        SrcLliTab_ptr[1] -= RemainingDataSize;
    }

    return;

} /* END OF SaSi_COMMON_CutAndSaveBeginOfLliData */
