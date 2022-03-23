/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: drv common header file
* Author: huawei
* Create: 2019/09/18
*/

#ifndef DRIVER_COMMON_H_
#define DRIVER_COMMON_H_

#ifndef NULL
#define NULL (void *)0
#endif

#ifdef STATIC_SKIP
#define STATIC
#else
#define STATIC static
#endif

#define NO_USE_PARAMETER(a) (void)(a)

#define BITS_PER_BYTE 8

#define BIT0 0x1
#define BIT1 0x2
#define BIT2 0x4
#define BIT3 0x8
#define BIT4 0x10
#define BIT5 0x20
#define BIT6 0x40
#define BIT7 0x80
#define BIT8 0x100
#define BIT9 0x200
#define BIT10 0x400
#define BIT11 0x800
#define BIT12 0x1000
#define BIT13 0x2000
#define BIT14 0x4000
#define BIT15 0x8000
#define BIT16 0x10000
#define BIT17 0x20000
#define BIT18 0x40000
#define BIT19 0x80000
#define BIT20 0x100000
#define BIT21 0x200000
#define BIT22 0x400000
#define BIT23 0x800000
#define BIT24 0x1000000
#define BIT25 0x2000000
#define BIT26 0x4000000
#define BIT27 0x8000000
#define BIT28 0x10000000
#define BIT29 0x20000000
#define BIT30 0x40000000
#define BIT31 0x80000000U

/* array index */
#define ARRAY_INDEX0 0
#define ARRAY_INDEX1 1
#define ARRAY_INDEX2 2
#define ARRAY_INDEX3 3
#define ARRAY_INDEX4 4
#define ARRAY_INDEX5 5
#define ARRAY_INDEX6 6
#define ARRAY_INDEX7 7
#define ARRAY_INDEX8 8

/* sfc img upgrade */
#define SFC_DATA_STORE_PADDR_BASE       0x1e00000
#define FLASH_SECTOR_SIZE               0x40000

static inline void dsb(void)
{
#ifndef DRIVER_DT_ENABLE
    asm volatile("dsb sy" ::: "memory");
#endif
}

#endif
