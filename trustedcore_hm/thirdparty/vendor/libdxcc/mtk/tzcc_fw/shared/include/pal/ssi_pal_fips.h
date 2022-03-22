/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_FIPS_H
#define _SSI_PAL_FIPS_H

/* !
@file
@brief This file contains definitions that are used by the FIPS related APIs. The implementation of these functions
need to be replaced according to Platform and OS.
*/

#include "ssi_pal_types_plat.h"
#include "sasi_fips.h"
#include "sasi_fips_defs.h"

/*
 * @brief This function purpose is to get the FIPS state.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
SaSiError_t SaSi_PalFipsGetState(CC_FipsState_t *pFipsState);

/*
 * @brief This function purpose is to get the FIPS Error.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
SaSiError_t SaSi_PalFipsGetError(CC_FipsError_t *pFipsError);

/*
 * @brief This function purpose is to get the FIPS trace.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
SaSiError_t SaSi_PalFipsGetTrace(CC_FipsTrace_t *pFipsTrace);

/*
 * @brief This function purpose is to set the FIPS state.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
SaSiError_t SaSi_PalFipsSetState(CC_FipsState_t fipsState);

/*
 * @brief This function purpose is to set the FIPS error.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
SaSiError_t SaSi_PalFipsSetError(CC_FipsError_t fipsError);

/*
 * @brief This function purpose is to set the FIPS trace.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
SaSiError_t SaSi_PalFipsSetTrace(CC_FipsTrace_t fipsTrace);

/*
 * @brief This function should push the FIPS TEE library error towards the REE library,
 *        the FIPS error can occur while running KAT tests at library init or while running
 *        conditional or continues tests
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
SaSiError_t SaSi_PalFipsNotifyUponTeeError(void);

#endif // _SSI_PAL_FIPS_H
