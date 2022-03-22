/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "stdio.h"
#include "ssi_pal_types.h"
#include "ssi_pal_error.h"
#include "ssi_pal_file.h"
#include "dx_pal_fileint.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* File modes table is constant table that handles the translations from DX_PAL modes to
   NoOS modes */
const SaSiPalFileModeStr_t SaSiPalFileModeTable[] = { { "r" },  { "r+" },  { "w" },  { "w+" },  { "a" },  { "a+" },
                                                      { "rb" }, { "r+b" }, { "wb" }, { "w+b" }, { "ab" }, { "a+b" } };

/* *********************** Private Functions **************************** */

/* *********************** Public Functions **************************** */
/*
 * @brief This function purpose is to return the file size
 *
 *
 * @param[in] aFileHandle - The file handle
 * @param[out] aFileSize - The returned file size
 *
 * @return The function will return SASI_SUCCESS in case of success, else errors from
 *         DX_PAL_Error.h will be returned.
 */
SaSiError_t SaSi_PalFGetFileSize(SaSiFile_t aFileHandle, uint32_t *aFileSize)
{
    /* position in file, size */
    uint32_t currPos = 0, fileSize = 0;

    /* error variable */
    SaSiError_t error = SASI_SUCCESS;

    /* ------------------
        CODE
    ------------------- */

    /* Get current position */
    currPos = SaSi_PalFTell(aFileHandle);

    /* Move pointer position to end fo file */
    error = SaSi_PalFSeek(aFileHandle, 0, SASI_PAL_SEEK_END);
    if (error != SASI_SUCCESS)
        return error;

    /* Get current position == size of file */
    fileSize = SaSi_PalFTell(aFileHandle);

    /* Return pointer to start position */
    error = SaSi_PalFSeek(aFileHandle, currPos, SASI_PAL_SEEK_START);
    if (error != SASI_SUCCESS)
        return error;

    *aFileSize = fileSize;

    return SASI_SUCCESS;

} /* End of SaSi_PalFGetFileSize */
