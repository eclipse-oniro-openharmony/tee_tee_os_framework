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

#ifndef _CC_CONFIG_FETRNG_H
#define _CC_CONFIG_FETRNG_H

#define CC_READ_REG(addr)    (*((volatile uint32_t *)(addr)))

#define CHIPID_ASIC          0x62901000
#define CHIPID_ASIC_N7       0x62901200
#define CHIPID_ASIC_N7_PLUS  0X62901100

/* sample count for each ring oscillator */
// for unallowed rosc, sample count = 0
#if defined(WITH_CHIP_HI3680)
#define CC_CONFIG_SAMPLE_CNT_ROSC_1             8600
#define CC_CONFIG_SAMPLE_CNT_ROSC_2             0
#define CC_CONFIG_SAMPLE_CNT_ROSC_3             12600
#define CC_CONFIG_SAMPLE_CNT_ROSC_4             14800
#elif defined(WITH_CHIP_ORLANDO)
#define CC_CONFIG_SAMPLE_CNT_ROSC_1             5900
#define CC_CONFIG_SAMPLE_CNT_ROSC_2             0
#define CC_CONFIG_SAMPLE_CNT_ROSC_3             22000
#define CC_CONFIG_SAMPLE_CNT_ROSC_4             17000
#elif defined(WITH_CHIP_KIRIN990)
#if defined(WITH_KIRIN990_CS2)
#define CC_CONFIG_SAMPLE_CNT_ROSC_1             9200
#define CC_CONFIG_SAMPLE_CNT_ROSC_2             8400
#define CC_CONFIG_SAMPLE_CNT_ROSC_3             8000
#define CC_CONFIG_SAMPLE_CNT_ROSC_4             7600
#elif defined(WITH_KIRIN990_CS) && defined(CONFIG_CDC)
#define CC_CONFIG_SAMPLE_CNT_ROSC_1             8800
#define CC_CONFIG_SAMPLE_CNT_ROSC_2             13650
#define CC_CONFIG_SAMPLE_CNT_ROSC_3             16500
#define CC_CONFIG_SAMPLE_CNT_ROSC_4             23000
#else
#define CC_CONFIG_SAMPLE_CNT_ROSC_1             10000
#define CC_CONFIG_SAMPLE_CNT_ROSC_2             28000
#define CC_CONFIG_SAMPLE_CNT_ROSC_3             30000
#define CC_CONFIG_SAMPLE_CNT_ROSC_4             13000
#endif
#elif defined(WITH_CHIP_DENVER) || defined(WITH_CHIP_BURBANK)
#define CC_CONFIG_SAMPLE_CNT_ROSC_1 \
	(CC_READ_REG(SCSOCID0) == CHIPID_ASIC_N7_PLUS ? 5300 : 7000)
#define CC_CONFIG_SAMPLE_CNT_ROSC_2 \
	(CC_READ_REG(SCSOCID0) == CHIPID_ASIC_N7_PLUS ? 8900 : 11000)
#define CC_CONFIG_SAMPLE_CNT_ROSC_3 \
	(CC_READ_REG(SCSOCID0) == CHIPID_ASIC_N7_PLUS ? 12000 : 0)
#define CC_CONFIG_SAMPLE_CNT_ROSC_4 \
	(CC_READ_REG(SCSOCID0) == CHIPID_ASIC_N7_PLUS ? 15000 : 21000)
#elif defined(WITH_CHIP_BALTIMORE) || defined(WITH_CHIP_LEXINGTON)
#define CC_CONFIG_SAMPLE_CNT_ROSC_1             1700
#define CC_CONFIG_SAMPLE_CNT_ROSC_2             2100
#define CC_CONFIG_SAMPLE_CNT_ROSC_3             2600
#define CC_CONFIG_SAMPLE_CNT_ROSC_4             2500
#else
#define CC_CONFIG_SAMPLE_CNT_ROSC_1             20000
#define CC_CONFIG_SAMPLE_CNT_ROSC_2             50000
#define CC_CONFIG_SAMPLE_CNT_ROSC_3             25000
#define CC_CONFIG_SAMPLE_CNT_ROSC_4             10000
#endif

#endif  // _CC_CONFIG_FETRNG_H
