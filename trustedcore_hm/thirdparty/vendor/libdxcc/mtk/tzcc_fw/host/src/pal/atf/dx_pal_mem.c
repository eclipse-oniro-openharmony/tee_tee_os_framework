/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "ssi_pal_types.h"
#include "ssi_pal_error.h"
#include "ssi_pal_mem.h"
#include "dx_pal_memint.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Private Functions **************************** */

/* *********************** Public Functions **************************** */

/*
 * @brief This function purpose is to perform secured memory comparison between two given
 *        buffers according to given size. The function will compare each byte till aSize
 *        number of bytes was compared even if the bytes are different.
 *        The function should be used to avoid security timing attacks.
 *
 *
 * @param[in] aTarget - The target buffer to compare
 * @param[in] aSource - The Source buffer to compare to
 * @param[in] aSize - Number of bytes to compare
 *
 * @return The function will return SASI_SUCCESS in case of success, else errors from
 *         DX_PAL_Error.h will be returned.
 */
SaSiError_t SaSi_PalSecMemCmp(const uint8_t *aTarget, const uint8_t *aSource, uint32_t aSize)
{
    /* internal index */
    uint32_t i = 0;

    /* error return */
    uint32_t error = SASI_SUCCESS;

    /* ------------------
        CODE
    ------------------- */

    /* Go over aTarget till aSize is reached (even if its not equal) */
    for (i = 0; i < aSize; i++) {
        if (aTarget[i] != aSource[i]) {
            if (error != SASI_SUCCESS)
                continue;
            else {
                if (aTarget[i] < aSource[i])
                    error = SASI_PAL_MEM_BUF2_GREATER;
                else
                    error = SASI_PAL_MEM_BUF1_GREATER;
            }
        }
    }

    return error;
} /* End of SaSi_PalSecMemCmp */
