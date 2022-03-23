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

#include "dx_pal_types.h"
#include "dx_pal_sem.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */
DX_PAL_SEM SemPkaId;
/* *********************** Private Functions **************************** */

/* *********************** Public Functions **************************** */

/* !
 * Init function for asymmetric code
 *
 * \return DxError_t - DX_OK
 */
DxError_t DX_ASYM_Init(void)
{
    DxError_t error;
    /* Initialize PKA's semaphore */
    error = DX_PAL_SemCreate(&SemPkaId, 1);

    return error;
}
