/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

// simple ECC library for tests

#include "pka_export.h"
#include "pka.h"
#include "pka_ecc.h"
#include "pka_ut.h"

#ifdef DEBUG
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#endif

void pka_point_copy(pka_point_t *to, pka_point_t *from)
{
    if (to != from) {
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, to->x, from->x);
        PKA_COPY(LEN_ID_N_PKA_REG_BITS, to->y, from->y);
    }
}

bool pka_point_on_curve(pka_point_t *p, uint32_t ec_a, uint32_t ec_b, uint32_t tt1, uint32_t tt2)
{
#define rl tt1
#define rr tt2
    bool res;
    PKA_MOD_MUL(LEN_ID_N_BITS, rl, p->y, p->y); // rl = y^2
    PKA_MOD_MUL(LEN_ID_N_BITS, rr, p->x, p->x); // rr = x^2
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rr, rr, ec_a);
    PKA_MOD_MUL(LEN_ID_N_BITS, rr, rr, p->x);     // rr = (x^2 + a).x
    PKA_ADD(LEN_ID_N_PKA_REG_BITS, rr, rr, ec_b); // rr = (x^2 + a).x + b
    PKA_REDUCE(LEN_ID_N_BITS, rl, rl);
    PKA_REDUCE(LEN_ID_N_BITS, rr, rr);
    PKA_COMPARE_STATUS(LEN_ID_N_PKA_REG_BITS, rr, rl, res); // res = rr == rl
#undef rl
#undef rr
    return ((bool)(res == 1));
}

bool pka_point_equal_p(pka_point_t *a, pka_point_t *b, uint32_t tt1, uint32_t tt2)
{
    return pka_mod_equal(a->x, b->x, tt1, tt2) && pka_mod_equal(a->y, b->y, tt1, tt2);
}
bool pka_point_zero_p(pka_point_t *p, uint32_t tt1, uint32_t tt2)
{
    return pka_mod_equal(p->x, 0 /* n */, tt1, tt2) && pka_mod_equal(p->y, 0 /* n */, tt1, tt2); // assume n = 0
}
