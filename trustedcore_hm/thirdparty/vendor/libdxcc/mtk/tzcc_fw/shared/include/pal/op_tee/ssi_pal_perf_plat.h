/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_PERF_PLAT_H__
#define _SSI_PAL_PERF_PLAT_H__

typedef unsigned int SaSi_PalPerfData_t;

/*
 * @brief   DSM environment bug - sometimes very long write operation.
 *        to overcome this bug we added while to make sure write opeartion is completed
 *
 * @param[in]
 * *
 * @return None
 */
void SaSi_PalDsmWorkarround();

#endif /* _SSI_PAL_PERF_PLAT_H__ */
