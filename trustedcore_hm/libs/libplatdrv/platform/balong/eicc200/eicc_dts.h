/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#ifndef _EICC_DTS_H
#define _EICC_DTS_H
#include "eicc_platform.h"

// No #define EICC_DTS_SUPPORT
/* can be defined in dts */
#define EICC_DEVICE_NUM_MAX 3
#define EICC_USRCHN_NUM_MAX 16

int eicc_init_meet(void);

struct eicc_srv_meminfo {
    u32 vmem_rsv_sz;
    u32 dmamem_rsv_sz;
    u32 pushmem_rsv_sz;
    u32 dump_size;
};
int eicc_reserved_meminfo(struct eicc_srv_meminfo *pmeminfo);
void *eicc_alloc_device(void);
void *eicc_alloc_device_bk(void);

#include "eicc_device.h"
struct eicc_proxy_dts {
    u32 user_id;
    u32 type;
    u32 ldrvchn_id;
    u32 rdrvchn_id;
    u32 const_flags;
};

struct eicc_chn_dts {
    u32 id;
    u32 type;
    u32 ldrvchn_id;
    u32 rdrvchn_id;
    u32 const_flags;
};

struct eicc_device_dts {
    u32 dev_id;
    u32 reg_addr;
    u32 reg_eaddr;
    u32 reg_size;
    u32 version_id;
    u32 pipepair_cnt;
    u32 ctrl_level;

    u32 irq_type;
    struct irq_bundle *maps[EICC_CPU_ID_MAX]; /* 大部分设备只有一组，这样节省内存 */

    struct eicc_chn_dts *child;
    u32 childcnt;
};

struct eicc_root_dts {
    u32 childcnt;
    u32 proxycnt;
    struct eicc_device_dts *child;
    struct eicc_proxy_dts *proxy;
};

struct eicc_root_dts *eicc_of_find_root_node(void);
struct eicc_device_dts *eicc_of_get_first_devnode(struct eicc_root_dts *np, struct eicc_device_dts *node);
struct eicc_device_dts *eicc_of_get_next_devnode(struct eicc_root_dts *np, struct eicc_device_dts *node);
struct eicc_chn_dts *eicc_of_get_first_chnnode(struct eicc_device_dts *np, struct eicc_chn_dts *node);
struct eicc_chn_dts *eicc_of_get_next_chnnode(struct eicc_device_dts *np, struct eicc_chn_dts *node);
struct eicc_proxy_dts *eicc_of_get_first_proxynode(struct eicc_root_dts *np, struct eicc_proxy_dts *node);
struct eicc_proxy_dts *eicc_of_get_next_proxynode(struct eicc_root_dts *np, struct eicc_proxy_dts *node);

#endif
