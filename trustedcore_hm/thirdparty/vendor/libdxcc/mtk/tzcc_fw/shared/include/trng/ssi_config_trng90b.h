/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SSI_CONFIG_TRNG90B_H
#define SSI_CONFIG_TRNG90B_H

/*
This file should be updated according to the characterization process.
*/

/*
Requirements:
- Required entropy = 384 bits

Default values for Zynq FPGA:
- entropy per bit = 0.5
*/

// amount of bytes for the required entropy bits = ROUND_UP(ROUND_UP(((required entropy bits)/(entropy per bit)), 1024),
// (EHR width in bytes)) / 8 (multiple of the window size 1024 bits and multiple of the EHR width 192 bits)
#define SSI_CONFIG_TRNG90B_AMOUNT_OF_BYTES 144 // ROUND_UP(ROUND_UP((384/0.5), 1024), 192) / 8 = 144

/* ** NIST SP 800-90B (2nd Draft) 4.4.1 * */
// C = ROUND_UP(1+(-log(W)/H)), W = 2^(-40), H=(entropy per bit)
#define SSI_CONFIG_TRNG90B_REPETITION_COUNTER_CUTOFF 81 // ROUND_UP(1+(40/0.5)) = 81

/* ** NIST SP 800-90B (2nd Draft) 4.4.2 * */
//  C =CRITBINOM(W, power(2,(-H)),1-a), W = 1024, a = 2^(-40), H=(entropy per bit)
#define SSI_CONFIG_TRNG90B_ADAPTIVE_PROPORTION_CUTOFF 823 // =CRITBINOM(1024, power(2,(-0.5)),1-2^(-40))

/* ** For Startup Tests * */
// amount of bytes for the startup test = 528 (at least 4096 bits (NIST SP 800-90B (2nd Draft) 4.3.12) = 22 EHRs = 4224
// bits)
#define SSI_CONFIG_TRNG90B_AMOUNT_OF_BYTES_STARTUP 528

/* sample count for each ring oscillator */
// for unallowed rosc, sample count = 0
#define SSI_CONFIG_SAMPLE_CNT_ROSC_1 1000
#define SSI_CONFIG_SAMPLE_CNT_ROSC_2 1000
#define SSI_CONFIG_SAMPLE_CNT_ROSC_3 500
#define SSI_CONFIG_SAMPLE_CNT_ROSC_4 0

#endif // SSI_CONFIG_TRNG90B_H
