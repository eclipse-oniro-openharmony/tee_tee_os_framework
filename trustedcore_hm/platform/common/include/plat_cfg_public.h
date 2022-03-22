/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg public defines for all platforms
 * Create: 2020-03
 */

#ifndef PLAT_CFG_PUBLIC_H
#define PLAT_CFG_PUBLIC_H

#include <stdint.h>
#include <arch/types.h>

#ifndef  PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define MAX_PROTECTED_REGIONS    16

#define GIC_V3_VERSION           3
#define GIC_V2_VERSION           2
#define PLAT_MAX_DEVIO_REGIONS   128
#define GICR_MAX_NUM             8
#define PLAT_CFG_ALIGNED_SIZE    (0x1000)
#define EXTEND_MAGIC             (0x5A5A5A5A)

struct gic_config_t {
    char version;
    union {
        struct v2_t {
            p_region_t dist;
            p_region_t contr;
        } v2;
        struct v3_t {
            p_region_t dist;
            uint32_t redist_num;
            uint32_t redist_stride;
            p_region_t redist[GICR_MAX_NUM];
        } v3;
    };
};

struct platform_info {
    uint64_t boot_args_size;
    uint64_t phys_region_size;
    paddr_t phys_region_start;
    uint64_t uart_addr;
#ifdef CONFIG_AARCH32_MONITOR
    paddr_t ns_kernel_info_paddr;
#endif
    /* 32~63 bit enable/disable flag && 0~31bit uart type flag */
    uint64_t uart_type;
    p_region_t protected_regions[MAX_PROTECTED_REGIONS];
    uint64_t shmem_offset;
    uint64_t shmem_size;
    uint32_t random_seed;
    struct gic_config_t gic_config;
    uint32_t spi_num_for_notify;
    uint64_t plat_features;
    union {
        struct extend_datas_t {
            uint64_t extend_magic;
            uint64_t extend_length;
            char extend_paras[0];
        } extend_datas;
        p_region_t plat_io_regions[PLAT_MAX_DEVIO_REGIONS];
    };
} __attribute__((__aligned__(PLAT_CFG_ALIGNED_SIZE)));

#endif
