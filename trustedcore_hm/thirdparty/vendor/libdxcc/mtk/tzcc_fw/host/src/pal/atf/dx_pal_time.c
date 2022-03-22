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

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Private Functions **************************** */

/* *********************** Public Functions **************************** */

/*
 * @brief This function returns the number of seconds passed from 1/1/1970 00:00 UTC.
 *
 *
 * @param[in] void
 *
 * @return Number of seconds passed from 1/1/1970 00:00 UTC
 */

int32_t SaSi_PalGetTime(void)
{
    /* No support for time utils in NoOS */
    return 0;
}
