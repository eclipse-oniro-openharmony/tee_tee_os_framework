/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */
// #ifndef PKA_POINT_COMPRESS_REGS_DEF_H
// #define PKA_POINT_COMPRESS_REGS_DEF_H

/* Definition of PKA_PointUncompress specific registers */

/* Uncompress point */
#define rN  0 // zP
#define rNp 1
/* stack */
#define rX   2
#define rY   3
#define rEcA 4
#define rEcB 5

/* Square root */
/* in */
#define rY1 rY /* 3 */   // zQ
#define rY2 rEcA /* 4 */ // zN
/* stack */
#define rT  6 // zT
#define rZ  7 // zZ
#define rEx 8 // zEx
#define rYt 9 // zYt

/* Jacoby symbol */
/* in */
#define rA 10 // za
#define rB 11 // zb
/* stack */
#define rC 12 // zc

// #endif
