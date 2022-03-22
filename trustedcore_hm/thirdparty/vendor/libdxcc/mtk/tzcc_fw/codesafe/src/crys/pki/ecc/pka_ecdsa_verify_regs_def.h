/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef PKA_ECDSA_VERIFY_REGS_DEF_H
#define PKA_ECDSA_VERIFY_REGS_DEF_H

/* Definition of ECDSA Verify specific registers */
#define rR    0
#define rnR   1
#define rF    2
#define rD    3
#define rh    4
#define rTmp  5
#define rh1   18
#define rh2   19
#define pG_x  20
#define pG_y  21
#define pW_x  22
#define pW_y  23
#define pR_x  24
#define pR_y  25
#define rn_t  26
#define rnp_t 27
#define rC    28
/* aliaces for pka2mul() */
#define a  rh1
#define b  rh2
#define xp pG_x
#define yp pG_y
#define xq pW_x
#define yq pW_y
#define xr pR_x
#define yr pR_y
#endif
