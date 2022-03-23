/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: define of sec mem
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#ifndef __TEE_DRV_MEM_LAYOUT_H
#define __TEE_DRV_MEM_LAYOUT_H

#include "hi_tee_drv_mem_layout.h"
#include "hi_tee_drv_os_hal.h"

/*
 * Suppress GCC warning on expansion of the macro with no argument:
 * 'ISO C99 requires at least one argument for the "..." in a variadic macro'
 * Occurs when '-pedantic' is combined with '-std=gnu99'.
 * Suppression applies only to this file and the expansion of macros defined in
 * this file.
 */
#pragma GCC system_header

#undef TEE_DRV_MEM_LAYOUT_DEBUG

#define mem_layout_printf(format, args...)  hi_tee_drv_hal_printf(format, ##args)
#define mem_layout_error(format, args...)   hi_tee_drv_hal_printf("[%s][%d][ERROR]"format, __func__, __LINE__, ##args)

#ifdef TEE_DRV_MEM_LAYOUT_DEBUG
#define mem_layout_debug(format, args...)   hi_tee_drv_hal_printf("[%s][%d][DEBUG]"format, __func__, __LINE__, ##args)
#else
#define mem_layout_debug(format, args...)
#endif


/* define DDR size */
#if defined(CFG_HI_TEE_DDR_SIZE_3_75G)
    #define DRAM0_SIZE                    0xF0000000
#elif defined(CFG_HI_TEE_DDR_SIZE_3G)
    #define DRAM0_SIZE                    0xC0000000
#elif defined(CFG_HI_TEE_DDR_SIZE_2G)
    #define DRAM0_SIZE                    0x80000000
#elif defined(CFG_HI_TEE_DDR_SIZE_1_5G)
    #define DRAM0_SIZE                    0x60000000
#elif defined(CFG_HI_TEE_DDR_SIZE_1G)
    #define DRAM0_SIZE                    0x40000000
#elif defined(CFG_HI_TEE_DDR_SIZE_512M)
    #define DRAM0_SIZE                    0x20000000
#elif defined(CFG_HI_TEE_DDR_SIZE_256M)
    #define DRAM0_SIZE                    0x10000000
#elif defined(CFG_HI_TEE_DDR_SIZE_NA)
    /* hi3796mv200/hi3796cv300 get DDR size by other way */
#endif

#define DDR_SIZE_MIN                      (256 * 1024 * 1024)

/* when the mem page size is 4K, max share region end is 0xFFFFFFFF */
#define MAX_SHARE_REGION_END              0x100000000ULL

#define SECTION_MASK                      0xFFF00000
/*
 * From begin of Hi3796cv300,the phy mem layout is like this, 0~128M is share
 * mem region0, 128M~216M is Reserved mem for tee, the left mem is the share mem
 * region1.
 *
-------------------------- MEM-LAYOUT in 3796CV300 begin   ------------------------------

    0x10000000  -------------------------------------------------------------
               290M   share mem region0
    0x22200000   -------------------------------------------------------------
                                    4M ATF
                    0x22600000 -------------------------------------
                                    4M Smmu pgt
                    0x22A00000 --------------------------------------
                                    2M Secure SMMU MMZ
                    0x22C00000 -------------------------------------
                fixed region        14M Secure MMZ
                    0x23A00000 --------------------------------------
                                    48M Secure OS
                    0x26A00000 --------------------------------------
                                    15M VMCU
                    0x27900000 --------------------------------------
                                    25M ADSP
                    0x29200000 --------------------------------------
                                    40M VQ6
                    0x2BA00000 --------------------------------------
                                    4M - 64k   Secure Reserve
                    0x2BDf0000 ----------------------------------------------
                                    64k Smmu r/w Dustbin
    0x2BE00000  ----------------------------------------------------------------
               XXX M  share mem region1
    DDR_SIZE    ----------------------------------------------------------------

-------------------------- MEM-LAYOUT in 3796CV300 end   --------------------------------
*/
#define TOTAL_TEE_SIZE                   0x9C00000   /* 156M */

/* share mem region0 */
#define NORMAL_MEM_START                 0x10000000
#define NORMAL_MEM_SIZE                  0x12200000   /* 290M */

#define SEC_OS_SIZE                      (TRUSTEDCORE_OS_MEM_SIZE * 1024 * 1024)
#define SEC_OS_START                     (TRUSTEDCORE_PHY_TEXT_BASE & SECTION_MASK)

#define SEC_MMZ_SIZE                     (TRUSTEDCORE_SEC_MMZ_MEM_SIZE * 1024 * 1024)
#define SEC_MMZ_START                    (SEC_OS_START - SEC_MMZ_SIZE)

#define SEC_SMMU_MMZ_SIZE                (TRUSTEDCORE_SEC_SMMU_MMZ_MEM_SIZE * 1024 * 1024)
#define SEC_SMMU_MMZ_START               (SEC_MMZ_START - SEC_SMMU_MMZ_SIZE)

#define SEC_SMMU_PAGETABLE_SIZE          (TRUSTEDCORE_SEC_SMMU_PAGETABLE_SIZE * 1024 * 1024)
#define SEC_SMMU_PAGETABLE_START         (SEC_SMMU_MMZ_START - SEC_SMMU_PAGETABLE_SIZE)

#define ATF_START                        (NORMAL_MEM_START + NORMAL_MEM_SIZE)
#define ATF_SIZE                         (SEC_SMMU_PAGETABLE_START - ATF_START)

#define VMCU_START                       (SEC_OS_SIZE + SEC_OS_START)
#define VMCU_SIZE                        (TRUSTEDCORE_VMCU_MEM_SIZE * 1024 * 1024)

#define ADSP_START                       (VMCU_START + VMCU_SIZE)
#define ADSP_SIZE                        (TRUSTEDCORE_ADSP_MEM_SIZE * 1024 * 1024)

#define VQ6_START                        (ADSP_START + ADSP_SIZE)
#define VQ6_SIZE                         (TRUSTEDCORE_VQ6_MEM_SIZE * 1024 * 1024)

#define SEC_SMMU_RW_ERR_SIZE             0x10000     /* 64K */
#define SEC_SMMU_RW_ERR_START            (ATF_START + TOTAL_TEE_SIZE - SEC_SMMU_RW_ERR_SIZE)

#define SEC_RESERVE_START                (VQ6_START + VQ6_SIZE)
#define SEC_RESERVE_SIZE                 (SEC_SMMU_RW_ERR_START - SEC_RESERVE_START)

#define TOTAL_TEE_MEM_BASE               ATF_START
#define TOTAL_TEE_MEM_SIZE               TOTAL_TEE_SIZE

#define SEC_MEM_VERIFY_REANGE_BASE       ATF_START
#define SEC_MEM_VERIFY_REANGE_SIZE       (SEC_RESERVE_START - ATF_START)


#if defined(TRUSTEDCORE_LARGER_MEM)
/*
 * if mem is larger then 2G, need a new region, and each region size must be agligend 64k*2^x.
 * So, the first norma region start at 0x80000000, and the NORMAL mem 7 end with 0x80000000 +
 * 0x6cb00000.
 */
#define TZASC_GAP_SIZE                  (2 * 0x10000)

#define SHARE_MEM_START                 NORMAL_MEM_START
#define SHARE_MEM_SIZE                  TRUSTEDCORE_SHAREMEM_SIZE

#define EXTRA_REE_MEM_START             (SHARE_MEM_START + SHARE_MEM_SIZE)
/*
 * The EXTRA_REE_MEM_SIZE must be align to 1M, because there are only 15 reserve regions that can be used.
 * If the EXTRA_REE_MEM_RGN_SIZE align size is less to 1M, there maybe not enough reserve regions to use.
 */
#define EXTRA_REE_MEM_RGN_SIZE          ((SEC_SMMU_RW_ERR_START - EXTRA_REE_MEM_START - TZASC_GAP_SIZE) & SECTION_MASK)
#else
#define SHARE_MEM_START                 NORMAL_MEM_START
#define SHARE_MEM_SIZE                  NORMAL_MEM_SIZE

#define EXTRA_REE_MEM_RGN_START         0
#define EXTRA_REE_MEM_RGN_SIZE          0
#endif

/* master id is defined by chip bus, shoud be move to platform */
#define BUS_MASTER_CPU              (1ULL << 0)
#define BUS_MASTER_GPU              (1ULL << 1)
#define BUS_MASTER_VMCU0            (1ULL << 2)
#define BUS_MASTER_SCIPHER          (1ULL << 3)
#define BUS_MASTER_SHA_SEC          (1ULL << 4)
#define BUS_MASTER_CIPHER           (1ULL << 5)
#define BUS_MASTER_SDIO             (1ULL << 6)
#define BUS_MASTER_PCIE             (1ULL << 7)
#define BUS_MASTER_USB2             (1ULL << 8)
#define BUS_MASTER_DDRT             (1ULL << 9)
#define BUS_MASTER_JPGD             (1ULL << 10)
#define BUS_MASTER_BPD              (1ULL << 11)
#define BUS_MASTER_JPGE             (1ULL << 12)
#define BUS_MASTER_VEDU             (1ULL << 13)
#define BUS_MASTER_PGD              (1ULL << 14)
#define BUS_MASTER_TDE              (1ULL << 15)
#define BUS_MASTER_VDP              (1ULL << 16)
#define BUS_MASTER_SPLCIPER         (1ULL << 17)
#define BUS_MASTER_AIAO             (1ULL << 18)
#define BUS_MASTER_CI               (1ULL << 19)
#define BUS_MASTER_VDH0             (1ULL << 20)
#define BUS_MASTER_SMCU             (1ULL << 21)
#define BUS_MASTER_TSIO             (1ULL << 22)
#define BUS_MASTER_PASTC            (1ULL << 23)
#define BUS_MASTER_RESERVE1         (1ULL << 24)
#define BUS_MASTER_RESERVE2         (1ULL << 25)
#define BUS_MASTER_VICAP            (1ULL << 26)
#define BUS_MASTER_TDMA             (1ULL << 27)
#define BUS_MASTER_VPSS             (1ULL << 28)
#define BUS_MASTER_DSP0             (1ULL << 29)
#define BUS_MASTER_PVR              (1ULL << 30)
#define BUS_MASTER_ETH              (1ULL << 31)
#define BUS_MASTER_DSP1             (1ULL << 32)
#define BUS_MASTER_VMCU_PREF        (1ULL << 33)
#define BUS_MASTER_NPU              (1ULL << 34)
#define BUS_MASTER_USB3             (1ULL << 35)
#define BUS_MASTER_SATA0            (1ULL << 36)
#define BUS_MASTER_UPS              (1ULL << 37)
#define BUS_MASTER_EMMC             (1ULL << 38)
#define BUS_MASTER_FMC              (1ULL << 39)
#define BUS_MASTER_VGS_BVT          (1ULL << 40)
#define BUS_MASTER_IVE_BVT          (1ULL << 41)
#define BUS_MASTER_VPSS_BVT         (1ULL << 42)
#define BUS_MASTER_KCF_BVT          (1ULL << 43)
#define BUS_MASTER_VMDA0            (1ULL << 44)
#define BUS_MASTER_VMCU1            (1ULL << 45)
#define BUS_MASTER_VMDA1            (1ULL << 46)
#define BUS_MASTER_RESERVE3         (1ULL << 47)
#define BUS_MASTER_RESERVE4         (1ULL << 48)
#define BUS_MASTER_RESERVE5         (1ULL << 49)
#define BUS_MASTER_RESERVE6         (1ULL << 50)
#define BUS_MASTER_RESERVE7         (1ULL << 51)
#define BUS_MASTER_VQ6_DSP0_CORE    (1Ull << 52)
#define BUS_MASTER_VQ6_DSP0_IDMA    (1Ull << 53)
#define BUS_MASTER_VQ6_DSP1_CORE    (1Ull << 54)
#define BUS_MASTER_VQ6_DSP1_IDMA    (1Ull << 55)

/* region master id */
#define RNG_MASTER_NONE                0x0ULL
#define RNG_MASTER_FULL                0xffffffffffffffffULL

#define RNG_MASTER_SEC_OS_R            (BUS_MASTER_CPU | BUS_MASTER_SHA_SEC)
#define RNG_MASTER_SEC_OS_W            BUS_MASTER_CPU

#define RNG_MASTER_SEC_MMZ_R           (BUS_MASTER_CPU | BUS_MASTER_CIPHER | BUS_MASTER_SHA_SEC)
#define RNG_MASTER_SEC_MMZ_W           (BUS_MASTER_CPU | BUS_MASTER_CIPHER)

#define RNG_MASTER_SEC_SMMU_MMZ_R      (BUS_MASTER_CPU | BUS_MASTER_SHA_SEC)
#define RNG_MASTER_SEC_SMMU_MMZ_W      BUS_MASTER_CPU

#define RNG_MASTER_SMMU_PT_R           RNG_MASTER_FULL
#define RNG_MASTER_SMMU_PT_W           BUS_MASTER_CPU

#define RNG_MASTER_SMMU_ERR_R          RNG_MASTER_FULL
#define RNG_MASTER_SMMU_ERR_W          RNG_MASTER_FULL

#define RNG_MASTER_ATF_R               (BUS_MASTER_CPU | BUS_MASTER_SHA_SEC)
#define RNG_MASTER_ATF_W               BUS_MASTER_CPU

#define RNG_MASTER_VMCU_R              (BUS_MASTER_CPU | BUS_MASTER_VMCU0 | BUS_MASTER_VMCU_PREF)
#define RNG_MASTER_VMCU_W              (BUS_MASTER_CPU | BUS_MASTER_VMCU0)

#define RNG_MASTER_ADSP_R              (BUS_MASTER_CPU | BUS_MASTER_DSP0 | BUS_MASTER_DSP1)
#define RNG_MASTER_ADSP_W              (BUS_MASTER_CPU | BUS_MASTER_DSP0 | BUS_MASTER_DSP1)

#define RNG_MASTER_VQ6_R               (BUS_MASTER_CPU | BUS_MASTER_VQ6_DSP0_CORE | BUS_MASTER_VQ6_DSP0_IDMA | \
                                        BUS_MASTER_VQ6_DSP1_CORE | BUS_MASTER_VQ6_DSP1_IDMA | BUS_MASTER_SHA_SEC)

#define RNG_MASTER_VQ6_W               (BUS_MASTER_CPU | BUS_MASTER_VQ6_DSP0_CORE | BUS_MASTER_VQ6_DSP0_IDMA | \
                                        BUS_MASTER_VQ6_DSP1_CORE | BUS_MASTER_VQ6_DSP1_IDMA)

#define RNG_MASTER_SHARE               RNG_MASTER_FULL

#endif /* _TEE_DRV_MEM_LAYOUT_H_ */
