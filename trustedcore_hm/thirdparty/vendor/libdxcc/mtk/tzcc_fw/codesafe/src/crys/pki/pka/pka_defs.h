/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef PKA_DEFS_H
#define PKA_DEFS_H

#include "ssi_sram_map.h"
#include "ssi_pal_types.h"
#include "ssi_pka_hw_plat_defs.h"

/* minimal and maximal allowed size of PKA data memory registers in bits */
#define PKA_MIN_OPERATION_SIZE_BITS SASI_BITS_IN_32BIT_WORD
#define PKA_MAX_OPERATION_SIZE_BITS (SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS + SASI_PKA_WORD_SIZE_IN_BITS)

#define SASI_SRAM_PKA_SIZE_IN_BYTES (SASI_PKA_SRAM_SIZE_IN_KBYTES * SASI_1K_SIZE_IN_BYTES)
#define SASI_SRAM_PKA_MAX_SIZE      SASI_SRAM_PKA_SIZE_IN_BYTES

/* PKA word size in bits/32bit words */
#define PKA_WORD_SIZE_IN_BYTES       (SASI_PKA_WORD_SIZE_IN_BITS / SASI_BITS_IN_BYTE)
#define PKA_WORD_SIZE_IN_32BIT_WORDS (SASI_PKA_WORD_SIZE_IN_BITS / SASI_BITS_IN_32BIT_WORD)

/* maximal size of extended register in "big PKA words" and in 32-bit words:  *
   the size defined according to RSA as more large, and used to define some   *
*  auxiliary buffers sizes                                */
#define PKA_MAX_REGISTER_SIZE_IN_PKA_WORDS \
    ((PKA_MAX_OPERATION_SIZE_BITS + PKA_EXTRA_BITS + SASI_PKA_WORD_SIZE_IN_BITS - 1) / SASI_PKA_WORD_SIZE_IN_BITS)
#define PKA_MAX_REGISTER_SIZE_IN_32BIT_WORDS (PKA_MAX_REGISTER_SIZE_IN_PKA_WORDS * PKA_WORD_SIZE_IN_32BIT_WORDS)

/* Full register (operation) size including extra PKA-word (128/64-bit). Op size *
*  must include extra bits if needed in the algorithm
// Adding 1 for operation with carry/additional bits               */
#define GET_FULL_OP_SIZE_PKA_WORDS(opSizeInBits) \
    ((((opSizeInBits) + SASI_PKA_WORD_SIZE_IN_BITS - 1) / SASI_PKA_WORD_SIZE_IN_BITS) + 1)
#define GET_FULL_OP_SIZE_BITS(opSizeInBits)        (SASI_PKA_WORD_SIZE_IN_BITS * GET_FULL_OP_SIZE_PKA_WORDS((opSizeInBits)))
#define GET_FULL_OP_SIZE_32BIT_WORDS(opSizeInBits) (GET_FULL_OP_SIZE_BITS((opSizeInBits)) / SASI_BITS_IN_32BIT_WORD)

/* The maximal count of allowed sizes of PKA operands or register-variables */
#define PKA_NUM_OF_PKA_LEN_IDS_REGS 8

/* enumerator, defining ID-s of PKA registers sizes, inserted in PKA sizes    *
 *  table                                                                      */
typedef enum {
    LEN_ID_N_BITS = 0,             // 0  - for modulus size
    LEN_ID_N_PKA_REG_BITS,         // 1  - for operation size
    LEN_ID_PQ_BITS,                // 2  - for P, Q size
    LEN_ID_PQ_PKA_REG_BITS,        // 3  - for operations on P, Q size
    LEN_ID_AUX_PRIME_BITS,         // 4  - for P1,P2,Q1,Q2 101 bit size
    LEN_ID_AUX_PRIME_PKA_REG_BITS, // 5  - for operations on P1,P2,Q1,Q2 101 bit size
    LEN_ID_NP_BITS,                // 6  - for calculating Np
    LEN_ID_MAX_BITS,               // 7  - size of PKA registers = SaSi_RSA_MAX_KEY_GENERATION_SIZE_BITS
    LEN_ID_MAX,                    // 8  - not allowed, indicates out of range
} LenIdTypes_t;

#endif // PKA_GEN_DEFS_H
