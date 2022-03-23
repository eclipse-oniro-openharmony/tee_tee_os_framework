/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#ifndef _CC_SRAM_MAP_H_
#define _CC_SRAM_MAP_H_

/*!
@file
@brief This file contains internal SRAM mapping definitions.
*/

#ifdef __cplusplus
extern "C"
{
#endif

#define CC_SRAM_PKA_BASE_ADDRESS                                0x0
#define CC_PKA_SRAM_SIZE_IN_KBYTES				  6


#define CC_SRAM_RND_HW_DMA_ADDRESS                              0x1800
#define CC_SRAM_RND_MAX_SIZE                                    0x800    /*!< Addresses 6K-8K in SRAM reserved for RND operations. */

#define CC_SRAM_MLLI_BASE_ADDR                                  0x2000
#define CC_SRAM_MLLI_MAX_SIZE                                   0x800    /*!< Addresses 8K-10K in SRAM reserved for MLLI tables. */

#define CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR               0x3C00
#define CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_LAST_WORD_ADDR     0x3FFC
#define CC_SRAM_DRIVER_ADAPTOR_CONTEXT_MAX_SIZE                 0x400    /*!< Last 1K, addresses 15K-16K, in SRAM reserved for driver adaptor context. */

#define CC_SRAM_MAX_SIZE                                        0x4000    /*!< SRAM total size is 16KB.  */

#ifdef __cplusplus
}
#endif

#endif /*_CC_SRAM_MAP_H_*/
