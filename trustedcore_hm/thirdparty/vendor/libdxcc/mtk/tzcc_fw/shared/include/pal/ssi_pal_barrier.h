/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_BARRIER_H
#define _SSI_PAL_BARRIER_H

/* !
@file
@brief This file contains the definitions and APIs for memory barrier implementation.
* This is a place holder for platform specific memory barrier implementation
* The secure core driver should include a memory barrier before and after the last word of the descriptor
* to allow correct order between the words and different descriptors.
*/

/* !
 * This macro is responsible to put the memory barrier after the write operation.
 *
 * @return None
 */

void SaSi_PalWmb(void);

/* !
 * This macro is responsible to put the memory barrier before the read operation.
 *
 * @return None
 */
void SaSi_PalRmb(void);

#endif
