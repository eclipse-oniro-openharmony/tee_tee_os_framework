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

#include "sasi.h"
#include "sasi_common_error.h"

/* .............. LLF level includes .................. */

#include "LLF_COMMON.h"
/* *********************** Defines **************************** */

/* *********************** MACROS **************************** */

/* *********************** Global Data **************************** */

/* ************ Private function prototype ************** */

/* *********************** Public Functions **************************** */

/* * ------------------------------------------------------------
 * @brief This function is used to operate bypass action.
 *
 *        The function executes the following major steps:
 *
 *        1.Checks the validation of all of the inputs of the function.
 *          If one of the received parameters is not valid it shall return an error.
 *
 *          The major checkers that are run over the received parameters:
 *          - verifying the pointer of the data_in buffer is not NULL.
 *          - verifying that the pointer to the data_out buffer is not NULL.
 *          - verifying the values of the data_in buffers size is not 0.
 *
 *
 *        2.executing bypass operation on the hardware.
 *        3.Exit the handler with the OK code.
 *
 *
 *          THERE IS AN ASSUMPTION THAT BYPASS IS ALAWYS FROM MEM TO SRAM
 *
 *
 * @param[in] DataIn_ptr - The pointer to the buffer of the input data. The pointer does
 *                   not need to be aligned.
 *
 * @param[in] DataInSize - The size of the input data.
 *
 * @param[in/out] DataOut_ptr - The pointer to the buffer of the output data . The pointer does not
 *                        need to be aligned to 32 bits.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* SaSi_AES_error.h
 */
CEXPORT_C SaSiError_t SaSi_COMMON_Bypass(uint8_t *DataIn_ptr, uint32_t DataInSize, uint8_t *DataOut_ptr)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    SaSiError_t Error;

    /* FUNCTION LOGIC */

    /* ............... local initializations .............................. */
    /* -------------------------------------------------------------------- */

    /* initializing the Error to O.K */
    Error = SaSi_OK;

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == NULL)

        return SaSi_COMMON_DATA_IN_POINTER_INVALID_ERROR;

    /* if the users Data Out pointer is illegal return an error */
    if (DataOut_ptr == NULL)

        return SaSi_COMMON_DATA_OUT_POINTER_INVALID_ERROR;

    /* if the data size is zero */
    if (DataInSize == 0)

        return SaSi_COMMON_DATA_SIZE_ILLEGAL;

    /* ................ checking the data in / out overlapping ............... */
    /* ----------------------------------------------------------------------- */

    /* checking that there is no overlapping between the data input and data out put buffer
       except the inplace case that is legal */
    if (DataIn_ptr != DataOut_ptr) {
        /* checking the case that the input buffer is in a higher address then the output buffer */
        if (DataIn_ptr > DataOut_ptr) {
            /* initialize the data out size as the data in size */
            uint32_t DataOutSize = DataInSize;

            /* if after adding the size to the data out pointer it is larger then the data in pointer
               return the overlap error */
            if (DataOut_ptr + DataOutSize > DataIn_ptr) {
                Error = SaSi_COMMON_DATA_OUT_DATA_IN_OVERLAP_ERROR;
                return Error;
            }

        } /* end of DataIn_ptr > DataOut_ptr */

        /* checking the case that the output buffer is in a higher address then the input buffer */
        else {
            /* if after adding the size to the data in pointer it is larger then the data out pointer
            return the overlap error */
            if (DataIn_ptr + DataInSize > DataOut_ptr) {
                Error = SaSi_COMMON_DATA_OUT_DATA_IN_OVERLAP_ERROR;
                return Error;
            }

        } /* end of DataOut_ptr > DataIn_ptr */

    } /* end of DataIn_ptr != DataOut_ptr case */

    /* .................. calling the hardware low level block function ....... */
    /* ------------------------------------------------------------------------ */

    Error = LLF_COMMON_Bypass_Block(DataIn_ptr,   /* the input data buffer - in */
                                    DataInSize,   /* the data in size - in */
                                    DataOut_ptr); /* the output data buffer i/o */

    if (Error != SaSi_OK) {
        return Error;
    }

    return SaSi_OK;

} /* END OF SaSi_COMMON_Bypass */
