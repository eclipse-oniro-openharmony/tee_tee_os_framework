/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */
#ifndef PKA_ECDSA_SIGN_REGS_DEF_H
#define PKA_ECDSA_SIGN_REGS_DEF_H

/* Definition of ECDSA SIGN specific registers */
/* pka_smul regs */
#define x2 12
#define y2 13
#define z2 14
#define t2 15
#define x4 16
#define y4 17
#define z4 18
#define t4 19
#define xs 20
#define ys 21
#define zs 22
#define ts 23
#define zp 24
#define tp 25
#define zr 26
/* k, p[in/out] */
#define ord 26 /* =zr, used for EC order */
#define rk  27 /* scalar */
#define xp  28 /* in/out */
#define yp  29 /* in/out */
#endif
