/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: hi_smmu
 * Author: Hisilicon
 * Create: 2009-12-16
 */
#ifndef __HI_SMMU_COMMON_H
#define __HI_SMMU_COMMON_H

#include <stddef.h>
#include <string.h>
#include "hi_list.h"
#include "hi_type_dev.h"
#include "hi_tee_drv_os_hal.h"

#ifdef CFG_HI_TEE_DPT_PLATFORM_SUPPORT
#define PASTC_BSE_REG 0xFF590000
#endif

#define PASTC_CTRL 0x0000
#define PASTC_INT 0x0004
#define PASTC_PAGE_SIZE 0x0008
#define PASTC_CLR_SET_NUM 0xc
#define PASTC_TTBR 0x0010
#define PASTC_START_ADDR 0x0014
#define PASTC_PAGE_NUM 0x0018
#define PASTC_TTBR_H 0x1c
#define PASTC_INT_MASK 0x0020
#define PASTC_INT_RAW 0x0024
#define PASTC_INT_STAT 0x0028
#define PASTC_INT_CLR 0x002c
#define PASTC_FAULT_RD_RESP_ADDR 0x0030
#define PASTC_FAULT_RD_INVALID_ADDR 0x0034
#define PASTC_FAULT_CLR_BRESP_PAGE 0x0038
#define PASTC_FAULT_CHECK_RESP_PAGE 0x003c
#define PASTC_FAULT_CHECK_ZERO_PAGE 0x0040

/* SMMU COMMON   */
#define SMMU_ERR_RDADDR_S 0x02f0
#define SMMU_ERR_WRADDR_S 0x02f4
#define SMMU_ERR_RWSIZE   0x100
#define SMMU_SCB_TTBR   0x208

#define SMMU_AGENT_ID 0x1234
#define HIL_MAX_NAME_LEN    16

#define REG_SC_GEN18    0x1448
#define REG_EC_STATUS_SHIFT	13
#define REG_EC_STATUS	0x2
#define REG_EC_STATUS_MASK	0x3

enum smmu_cmd_t {
    HISI_MEM_ALLOC = 0x0,
    HISI_MEM_FREE,
    HISI_MEM_GET_MEMINFO,
    HISI_MEM_PUT_MEMINFO,
    HISI_AGENT_CLOSE,
};

struct sec_mmb {
    char name[HIL_MAX_NAME_LEN];
    unsigned long long sec_smmu;
    unsigned long long phys_addr;
    unsigned long long meminfo_addr; /* page info address  */
    unsigned int nblocks; /* nr blocks for sg pages */
    unsigned long long tz_memblocks;
    int memtype;  /* 1: system mem  0:cma mem  */
    unsigned long long size;
    void *sec_virt;
    int flag;       /* indicate whether the mem is secure or not */
    int t_ref;      /* t_ref : smmu_ref + map_ref */
    int smmu_ref;
    int map_ref;
    int kmap_ref;
    char *uuid;
    unsigned long long nosec_smmu; /* for normal mem to map sec cpu or sec smmu */
    int cached;
    struct list_head list;
    struct list_head t_list;
    int is_smmu_map_clear; /* indicate the smmu map if clear. 1: clear; 0 : no clear  */
    void *v_meminfo;
    unsigned int ssm_tag;
    int istagset;  /* 0:smmu tag is default,not set,  1: smmu tag is set  */
    unsigned long long handle_id;
};

struct smmu_ctrl_t {
    enum smmu_cmd_t cmd;
    int memtype; // 0:cma mem; 1: system mem
    char name[HIL_MAX_NAME_LEN];
    unsigned long long size;
    unsigned long long phys_addr;
    unsigned long long normal_smmu;
    unsigned long long sec_smmu;
    unsigned long long tz_mblock_phys;
    unsigned long long private_data_phys;
    unsigned long long private_size;
    unsigned long long handle_id;
    unsigned long long reserved;
};

extern struct list_head g_smmu_list;
extern struct hi_tee_hal_mutex g_smmu_lock;

inline void smmu_mutex_lock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_lock(lock);
}

inline void smmu_mutex_unlock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_unlock(lock);
}

int check_mem_secure_attr(unsigned long long pageinfo,
                          unsigned long long total_size,
                          unsigned int nblocks, int *result);

int hi_smmu_suspend(void);

int hi_smmu_resume(void);

int smmu_init(void);

unsigned long get_shrm_size();

/* ree mmz drvier ops */
int ree_ops_alloc_buffer(const char *bufname, unsigned long size, int memtype,
                         struct smmu_ctrl_t *smmu_ctrl_temp);

int ree_ops_free_buffer(int memtype, unsigned long long phys_addr, unsigned long long nosec_smmu,
                        unsigned long long sec_smmu, unsigned long long buf_phys);

int ree_mmz_ops_get_meminfo(unsigned long long nonsec_addr, int memtype, struct smmu_ctrl_t *smmu_ctrl_temp);

int ree_mmz_ops_put_meminfo(unsigned long long phys_addr, unsigned long long nosec_smmu, int memtype,
                            unsigned long long buf_phys, unsigned long long handle_id);

int dump_mem(void);

int insert_sec_mmb(struct sec_mmb *sec_mmb);

struct sec_mmb *get_sec_mmb_by_handle_id(unsigned long long handle_id);

struct sec_mmb *get_sec_mmb_by_secsmmu(unsigned long long sec_smmu);

struct sec_mmb *get_sec_mmb_by_phys(unsigned long long phys_addr);

struct sec_mmb *get_sec_mmb_by_secvirt(void *sec_virt);

struct sec_mmb *get_sec_mmb_by_nosecsmmu(unsigned long long nosec_smmu);

int smmu_set_sec_flags(unsigned long long sec_smmu, unsigned long long size);

int smmu_clear_sec_flags(unsigned long long sec_smmu, unsigned long long size);

int delete_sec_mmb(struct sec_mmb *sec_mmb);

unsigned int replenish_secmmb_info_by_secsmmu(struct sec_mmb *sec_mmb, const char *bufname,
                                              unsigned long long normal_smmu);
#endif
