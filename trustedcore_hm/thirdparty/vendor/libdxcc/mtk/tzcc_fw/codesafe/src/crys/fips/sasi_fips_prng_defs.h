/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SaSi_FIPS_PRNG_DEFS_H
#define _SaSi_FIPS_PRNG_DEFS_H

#include "sasi_rnd.h"

CC_FipsError_t SaSi_FipsPrngKat(SaSi_RND_Context_t *pRndContext, SaSi_PrngFipsKatCtx_t *pPrngCtx);

#endif // _SaSi_FIPS_PRNG_DEFS_H
