/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef __DX_REG_BASE_HOST_H__
#define __DX_REG_BASE_HOST_H__

/* !
@file
@brief This file contains general HW related definitions.
*/

/* ! Identify platform: Xilinx Zynq7000 ZC706 */
#define DX_PLAT_ZYNQ7000       1
#define DX_PLAT_ZYNQ7000_ZC706 1

/* ! SEP core clock frequency in MHz */
#define DX_SEP_FREQ_MHZ 50

/* ! Base address for ARM TrustZone CryptoCell TEE registers. It must be modified to match the mapping of ARM TrustZone
 * CryptoCell TEE on the customer's * platform. */
#define DX_BASE_CC    0x10210000
#define DX_CLOCK_BASE 0x10001000

/* ! Base address for FPGA environment registers */
#define DX_BASE_ENV_REGS        0x40008000
#define DX_BASE_ENV_CC_MEMORIES 0x40008000
#define DX_BASE_ENV_PERF_RAM    0x40009000

#define DX_BASE_HOST_RGF   0x0UL
#define DX_BASE_CRY_KERNEL 0x0UL
#define DX_BASE_ROM        0x40000000

#define DX_BASE_RNG 0x0000UL
#endif /* __DX_REG_BASE_HOST_H__ */
