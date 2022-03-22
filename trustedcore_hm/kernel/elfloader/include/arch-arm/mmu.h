/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: arm mmu configs
 * Create: 2021-03
 */
#ifndef ELFLOADER_MMU_H
#define ELFLOADER_MMU_H

#define BOOT_OFFSET          (0x8000)

/*
 * mmu mapping regions should not be larger than ELFLOADER_MAP_SIZE
 * as pagetable items may take up too much space
 */
#define ELFLOADER_MAP_SIZE   (0x3000000)

#define USER_LEVEL0_OFFSET   (0x0)
#define USER_LEVEL1_OFFSET   (0x1000)
#define USER_LEVEL2_OFFSET   (0x2000)

#define KERNEL_LEVEL0_OFFSET (0x3000)
#define KERNEL_LEVEL1_OFFSET (0x4000)
#define KERNEL_LEVEL2_OFFSET (0x5000)
#define DEVICE_LEVEL2_OFFSET (0x6000)

#define PMD_ORDER               (3U)

#define KERNEL_ALIGN_SIZE       (1 << 20)

#define MAIR_ATTR_SET(attr, index) (((uint64_t)attr) << ((index) << 3))

#define MAIR_ATTR_DEVICE                (0x4)
#define MAIR_ATTR_IWBWA_OWBWA_NTR       (0xff)

#define MAIR_ATTR_DEVICE_INDEX          0x1
#define MAIR_ATTR_IWBWA_OWBWA_NTR_INDEX 0x0

#define MMU_VALID_TABLE_FLAG            (0x3)
#define MMU_BLOCK_FLAG                  (0x1)
#define MMU_TABLE_FLAG                  (0x3)
#define PTE_AF_ATTR                     (1U << 10)
#define MEM_SHARE_ATTR                  (3U << 8)
#define MEM_DEVICE_NGNRNE_TYPE          0U
#define MEM_MT_NORMAL                   4U
#define PTE_ATTRIDX(a)                  ((a) << (2U))
#define TCR_IPS_OFFSET                  (0x20)

#define MAIR_DEVICE_NGNRNE              (0U << 0)
#define MAIR_DEVICE_NGNRE               (4U << 8)
#define MAIR_DEVICE_GRE                 (0xc << 16)
#define MAIR_NORMAL_NC                  (0x44 << 24)
#define MAIR_NORMAL                     (0xff << 32)

#define BIT32(nr)   (1U << (nr))

#define SCTLR_M     BIT32(0)
#define SCTLR_A     BIT32(1)
#define SCTLR_C     BIT32(2)
#define SCTLR_SA    BIT32(3)
#define SCTLR_I     BIT32(12)
#define SCTLR_WXN   BIT32(19)

#define ACCESS_READ  0x0
#define ACCESS_WRITE 0x1

#endif /* ELFLOADER_MMU_H */
