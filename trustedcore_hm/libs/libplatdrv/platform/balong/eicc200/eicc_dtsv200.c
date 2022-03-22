/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#include "eicc_platform.h"
#include "eicc_dts.h"

#include "eicc_device.h"
#include "eicc_driver.h"
#include "eicc_core.h"

#define EICC_DEVICE_NUM_TOTAL 3
#define EICC_DEVICE_NUM_ASSIGN 2
#define EICC_DEVICE_NUM_HOSTED 0
#if EICC_DEVICE_NUM_TOTAL > EICC_DEVICE_NUM_MAX
#error "EICC_DEVICE_NUM_MAX must be enough"
#endif

#define EICC_MEM_PREALLOC_SIZE 0
#define EICC_PUSHMEM_PREALLOC_SIZE 512
#define EICC_DMAMEM_PREALLOC_SIZE (1024 * 2)
#define EICC_DUMP_FIELD_SIZE 0

struct eicc_device g_eicc_devices[EICC_DEVICE_NUM_TOTAL];

int eicc_init_meet(void)
{
    return 1;
}

int eicc_reserved_meminfo(struct eicc_srv_meminfo *pmeminfo)
{
    pmeminfo->vmem_rsv_sz = EICC_MEM_PREALLOC_SIZE;
    pmeminfo->pushmem_rsv_sz = EICC_PUSHMEM_PREALLOC_SIZE;
    pmeminfo->dmamem_rsv_sz = EICC_DMAMEM_PREALLOC_SIZE;
    pmeminfo->dump_size = EICC_DUMP_FIELD_SIZE;
    return 0;
}

void *eicc_alloc_device(void)
{
    static u32 idx = 0;
    struct eicc_device *pdev = NULL;
    if (idx < EICC_DEVICE_NUM_TOTAL) {
        pdev = &g_eicc_devices[idx];
        idx++;
    }
    return pdev;
}
void *eicc_alloc_device_bk(void)
{
    return NULL;
}
/* clang-format off */
struct eicc_proxy_dts g_eicc_proxy_chns[] = {
    {
        .user_id = EICC_CHN_RECV_TSP2AP_MDRV_LLT,
        .type = EICC_CHN_TYPE_MSG_OUTRECV,
        .ldrvchn_id = 0x00000004,
        .rdrvchn_id = 0x10000400,
        .const_flags = 0x0,
    },
    {
        .user_id = EICC_CHN_SEND_AP2TSP_MDRV_LLT,
        .type = EICC_CHN_TYPE_MSG_OUTSEND,
        .ldrvchn_id = 0x00010004,
        .rdrvchn_id = 0x10010400,
        .const_flags = 0x20000000,
    },
    {
        .user_id = EICC_CHN_RECV_TSP2AP_MDRV_MSG,
        .type = EICC_CHN_TYPE_MSG_OUTRECV,
        .ldrvchn_id = 0x00040004,
        .rdrvchn_id = 0x10040400,
        .const_flags = 0x0,
    },
    {
        .user_id = EICC_CHN_SEND_AP2TSP_MDRV_MSG,
        .type = EICC_CHN_TYPE_MSG_OUTSEND,
        .ldrvchn_id = 0x00050004,
        .rdrvchn_id = 0x10050400,
        .const_flags = 0x20000000,
    },
    {
        .user_id = EICC_CHN_RECV_TSP2AP_MDRVNV,
        .type = EICC_CHN_TYPE_MSG_OUTRECV,
        .ldrvchn_id = 0x000C0004,
        .rdrvchn_id = 0x100C0400,
        .const_flags = 0x0,
    },
    {
        .user_id = EICC_CHN_SEND_AP2TSP_MDRVNV,
        .type = EICC_CHN_TYPE_MSG_OUTSEND,
        .ldrvchn_id = 0x000D0004,
        .rdrvchn_id = 0x100D0400,
        .const_flags = 0x20000000,
    },
    {
        .user_id = EICC_CHN_RECV_TSP2AP_MDRVRFILE,
        .type = EICC_CHN_TYPE_MSG_OUTRECV,
        .ldrvchn_id = 0x000E0004,
        .rdrvchn_id = 0x100E0400,
        .const_flags = 0x0,
    },
    {
        .user_id = EICC_CHN_SEND_AP2TSP_MDRVRFILE,
        .type = EICC_CHN_TYPE_MSG_OUTSEND,
        .ldrvchn_id = 0x000F0004,
        .rdrvchn_id = 0x100F0400,
        .const_flags = 0x20000000,
    },
    {
        .user_id = EICC_CHN_RECV_LPM2AP_MDRV_MSG,
        .type = EICC_CHN_TYPE_MSG_INRRECV,
        .ldrvchn_id = 0x00100003,
        .rdrvchn_id = 0x00100300,
        .const_flags = 0x0,
    },
    {
        .user_id = EICC_CHN_SEND_AP2LPM_MDRV_MSG,
        .type = EICC_CHN_TYPE_MSG_INRSEND,
        .ldrvchn_id = 0x00110003,
        .rdrvchn_id = 0x00110300,
        .const_flags = 0x0,
    },

};

struct eicc_chn_dts g_eicc_channels_dts[] = {
    {EICC_CHN_RECV_TSP2TEE_MDRV_MSG, EICC_CHN_TYPE_MSG_OUTRECV, 0x00060104, 0x10060401, 0},
    {EICC_CHN_SEND_TEE2TSP_MDRV_MSG, EICC_CHN_TYPE_MSG_OUTSEND, 0x00070104, 0x10070401, 0},
};

static struct irq_bundle bundles[]={
    {
        .cpu_id = 1,
        .irq = { 276, 277 },
    },
    {
        .cpu_id = 1,
        .irq = { 278, 0xffffffff },
    },
};

struct eicc_device_dts g_eicc_devices_dts[] = {
    {
        .dev_id = 0,
        .reg_addr = 0xE5040000,
        .reg_eaddr = 0xE5040000,
        .reg_size = 0x8000,
        .version_id = 0x32303061,
        .pipepair_cnt = 32,
        .ctrl_level = EICC_DEV_CONTROL_LEVEL_GUEST,

        .irq_type = EICC_IRQ_TYPE_OIMERG,
        .maps = {[1] = &bundles[0]},

        .child = g_eicc_channels_dts,
        .childcnt = sizeof(g_eicc_channels_dts) / sizeof(g_eicc_channels_dts[0]),
    },
    {
        .dev_id = 1,
        .reg_addr = 0xE0B00000,
        .reg_eaddr = 0xE0B00000,
        .reg_size = 0x8000,
        .version_id = 0x32303061,
        .pipepair_cnt = 48,
        .ctrl_level = EICC_DEV_CONTROL_LEVEL_IRQCLR,

        .irq_type = EICC_IRQ_TYPE_OIMERG,
        .maps = { [1] = &bundles[1] },
    },
};
/* clang-format on */
static struct eicc_root_dts g_eicc_dtsroot = {
    .childcnt = sizeof(g_eicc_devices_dts) / sizeof(g_eicc_devices_dts[0]),
    .proxycnt = sizeof(g_eicc_proxy_chns) / sizeof(g_eicc_proxy_chns[0]),
    .child = g_eicc_devices_dts,
    .proxy = g_eicc_proxy_chns,
};
struct eicc_root_dts *eicc_of_find_root_node(void)
{
    return &g_eicc_dtsroot;
}
struct eicc_device_dts *eicc_of_get_first_devnode(struct eicc_root_dts *np, struct eicc_device_dts *node)
{
    UNUSED(node);
    if (np == NULL) {
        return NULL;
    }
    return np->child;
}

struct eicc_device_dts *eicc_of_get_next_devnode(struct eicc_root_dts *np, struct eicc_device_dts *node)
{
    if (np == NULL || np->child > node) {
        return NULL;
    }
    node++;
    if (node >= np->child + np->childcnt) {
        return NULL;
    }
    return node;
}
struct eicc_chn_dts *eicc_of_get_first_chnnode(struct eicc_device_dts *np, struct eicc_chn_dts *node)
{
    UNUSED(node);
    if (np == NULL) {
        return NULL;
    }
    return np->child;
}

struct eicc_chn_dts *eicc_of_get_next_chnnode(struct eicc_device_dts *np, struct eicc_chn_dts *node)
{
    if (np == NULL || np->child > node) {
        return NULL;
    }
    node++;
    if (node >= np->child + np->childcnt) {
        return NULL;
    }
    return node;
}

struct eicc_proxy_dts *eicc_of_get_first_proxynode(struct eicc_root_dts *np, struct eicc_proxy_dts *node)
{
    UNUSED(node);
    if (np == NULL) {
        return NULL;
    }
    return np->proxy;
}

struct eicc_proxy_dts *eicc_of_get_next_proxynode(struct eicc_root_dts *np, struct eicc_proxy_dts *node)
{
    if (np == NULL || np->proxy > node) {
        return NULL;
    }
    node++;
    if (node >= np->proxy + np->proxycnt) {
        return NULL;
    }
    return node;
}
