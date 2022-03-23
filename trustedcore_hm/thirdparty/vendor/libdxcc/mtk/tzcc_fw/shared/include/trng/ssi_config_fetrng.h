/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SSI_CONFIG_FETRNG_H
#define SSI_CONFIG_FETRNG_H

/* sample count for each ring oscillator */
// for unallowed rosc, sample count = 0
#if defined(WITH_CHIP_MT6873) || defined(WITH_CHIP_MT6853) || defined(WITH_CHIP_MT6768) || defined(WITH_CHIP_MT6885)
#define SSI_CONFIG_SAMPLE_CNT_ROSC_1 10000
#define SSI_CONFIG_SAMPLE_CNT_ROSC_2 10000
#define SSI_CONFIG_SAMPLE_CNT_ROSC_3 10000
#define SSI_CONFIG_SAMPLE_CNT_ROSC_4 10000
#else
#define SSI_CONFIG_SAMPLE_CNT_ROSC_1 1000
#define SSI_CONFIG_SAMPLE_CNT_ROSC_2 1000
#define SSI_CONFIG_SAMPLE_CNT_ROSC_3 500
#define SSI_CONFIG_SAMPLE_CNT_ROSC_4 0
#endif

#endif // SSI_CONFIG_FETRNG_H
