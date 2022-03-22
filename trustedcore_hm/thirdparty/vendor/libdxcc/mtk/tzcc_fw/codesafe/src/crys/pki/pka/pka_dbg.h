/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef PKA_DBG_H
#define PKA_DBG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_pal_types.h"
#include "pka_hw_defs.h"

#ifdef GMP_DEBUG
#include "gmp-utils.h"
#endif

#ifdef PKA_DEBUG

#include <stdio.h>
#include "ssi_pal_abort.h"
#define PKA_PRINTF printf
#define ASSERT(x)         \
    if (!(x)) {           \
        SaSi_PalAbort(x); \
    }
/* if the value is defined, then debug printing is performed
in the parts of code, where the global variable gDoDebugPrint
is set to 1 in run time */
// #define DBG_PRINT_ON_FAIL_ONLY 1
// #define USE_GMP_TEST_DEBUG_BUFFER 1
// #define ECC_DEBUG 1

/* reference to temp buffers used for debugging of PKA operations */
#ifdef DEBUG
extern uint32_t tempRes[PKA_MAX_REGISTER_SIZE_IN_32BIT_WORDS];
extern uint32_t tempRes1[PKA_MAX_REGISTER_SIZE_IN_32BIT_WORDS];
#endif

/*
 * The function prints label and PKA register as big endian bytes array.
 *
 * @author reuvenl (8/25/2013)
 *
 * @param label - label string.
 * @param reg - register virt. pointer.
 */
void pka_reg_print(const char *label, const uint32_t reg);

/*
 * The function prints the label and 32-bit words buffer (LS-word is
 * a left most) as a big hexadecimal number (MS-digit is a left most).
 *
 * @param label - label string.
 * @param pBuf - 32-bit words buffer to print.
 * @param sizeWords - size of pBuff in 32-bi words.
 */
void pka_buf_print(const char *label, const uint32_t *pBuf, uint32_t sizeWords);

/*
 * Print EC m-point as affine.
 *
 * @author reuvenl (3/16/2015)
 *
 * @param rx, ry, rz, rt - coordinates (pka regs).
 */
void pka_printMp2Ap(uint32_t rx, uint32_t ry, uint32_t rz, uint32_t rt);

/*
 * Print EC m-point as affine.
 *
 * @author reuvenl (3/16/2015)
 *
 * @param rx, ry, rz, - j-point coordinates (pka regs).
 */
void pka_printJp2Ap(uint32_t rx, uint32_t ry, uint32_t rz);

/* Special debug prints */
#define PKA_START_FUNC  printf("\n[ %s\n", __func__)
#define PKA_FINISH_FUNC printf("] %s\n", __func__)
#define PPR(reg)  \
    printf(#reg); \
    pka_reg_print("=", reg)
#define PPB(buf, size)                 \
    {                                  \
        printf(#buf);                  \
        pka_buf_print("=", buf, size); \
    }

#define PPMP(x, y, z, t) pka_printMp2Ap(x, y, z, t)
#define PPJP(x, y, z)    pka_printJp2Ap(x, y, z)

/* ************************************ */
#else // not PKA_DEBUG

#define pka_reg_print(label, reg)
#define pka_buf_print(label, pBuf, sizeWords)
// #define pka_printJp2Ap(rx, ry, rz)

#define PKA_PRINTF(format, ...) \
    do {                        \
    } while (0)
#define ASSERT(x) \
    do {          \
    } while (0)
#define PKA_START_FUNC
#define PKA_FINISH_FUNC
#define PPR(reg)
#define PPB(buf, size)
#define PPMP(x, y, z, t)
#define PPJP(x, y, z)

#endif /* end of if/else PKA_DEBUG */

#ifdef __cplusplus
}
#endif

#endif
