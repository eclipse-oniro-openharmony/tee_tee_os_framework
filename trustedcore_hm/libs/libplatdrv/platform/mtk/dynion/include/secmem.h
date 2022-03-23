/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: just copy for compile, delete in EMUI trunk
 * Author: Heyanhong heyanhong2@huawei.com
 * Create: 2020-09-14
 */
/*
 * copy from hisi secmem, just for compile dynion_config
 * in EMUI trunk, this will use hisi secmem.h directly
 */
#ifndef SECMEM_SECMEM_H
#define SECMEM_SECMEM_H
#include <sre_typedef.h>
#include <stdint.h>
#include <mem_page_ops.h>

enum mem_input_type {
    MEM_INPUT_ADDR,    /* phy addr */
    MEM_INPUT_BUFFID,  /* sfd or sec handle */
    MEM_INPUT_SCATTER, /* pglist */
    MEM_INPUT_MAX
};

enum secure_mode_t {
    MODE_NON_SECURE,
    MODE_SECURE,
};

enum cache_mode_t {
    MODE_NON_CACHE,
    MODE_CACHE,
};

typedef struct _mem_cfg_para {
    int mem_type;
    unsigned int in_type;
    union {
        struct {
            paddr_t phy_addr;
            uint32_t size;
        }para_addr;
        struct {
            uint64_t buffer_id;
            uint32_t size;
        }para_id;
        struct {
            struct page_info *pageinfo;
            uint32_t nents;
        }para_scatter;
    } input;
} mem_cfg_para_s;

/* just for compile */
inline int secmem_sec_cfg(mem_cfg_para_s *meminfo, int svc_id, int opt)
{
    (void)meminfo;
    (void)svc_id;
    (void)opt;
    return 0;
}
inline int secmem_sec_check(mem_cfg_para_s *meminfo, int svc_id)
{
    (void)meminfo;
    (void)svc_id;
    return 0;
}

#endif
