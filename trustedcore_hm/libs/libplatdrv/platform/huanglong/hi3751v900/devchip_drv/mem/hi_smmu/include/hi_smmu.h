/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: hi_smmu
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#ifndef _HI_SMMU_H
#define _HI_SMMU_H

#include "sre_access_control.h"
#include "hmdrv_stub.h"
#include "hi_smmu_common.h"

#ifndef TA_SMMU_AGENT_SUSPEND
#define TA_SMMU_AGENT_SUSPEND       0xFFFE
#endif

#define UUID_LENGTH 16

struct tz_memblocks {
    unsigned int total_size;
    unsigned long long sec_smmu;
    unsigned long long phys_addr;
    unsigned long long normal_smmu;
    unsigned long long pageinfoaddr;
    unsigned long long nblocks;
    unsigned long long private_data;
    unsigned int private_len;
    unsigned int isprivate;
    unsigned long long handle_id;
};

#define HI_MEM_PROC 0x2005

enum smmu_drv_ioctl_cmd_id {
    HISI_SEC_MAPTOSMMU = 0x0,
    HISI_SEC_UNMAPFROMSMMU,
    HISI_SEC_MAPTOSMMU_AND_SETFLAG,
    HISI_SEC_UNMAPFROMSMMU_AND_CLRFLG,
    HISI_SEC_ALLOC,
    HISI_SEC_FREE,
    HISI_NOSEC_MEM_MAP_TO_SEC_SMMU,
    HISI_NOSEC_MEM_UNMAP_FROM_SEC_SMMU,
    AGENT_CLOSED,
    SEC_IOCTL,
    CHECK_SEC_SMMU,
    CHECK_SEC_MMZ,
    HI_SECSMMU_COMMON_AGENT_SUSPEND = 0x3001,
    HI_SECSMMU_COMMON_AGENT_RESUME = 0x3002,
};
struct hi_tee_smmu_ioctl_data {
    char *bufname;
    unsigned long long phys_addr;
    unsigned long long sec_addr;
    unsigned long long nonsec_addr;
    unsigned long long buf_phys;
    unsigned long long buf_size;
    unsigned long long smmu_addr;
    unsigned long long cmd;
    unsigned long long arg0;
    unsigned long long arg1;
    int memtype;
    int share_mem;
    enum smmu_drv_ioctl_cmd_id cmd_id;
};

int smmu_hardware_resume(void);

int smmu_common_init_s(unsigned long long smmu_e_raddr, unsigned long long smmu_e_waddr, unsigned long long smmu_pgtbl);

/*
 * func: map to sec-smmu
 * buf_phys: input, buffer phy_addr from no secure world, which store the mem info
 * buf_size: input, buffer size
 * return: sec-smmu addr if exec success
 *     0 if exec failed
 */
unsigned int hisi_sec_maptosmmu(unsigned long long buf_phys, unsigned long long buf_size);

/*
 * func: unmap from sec-smmu
 * buf_phys: input, buffer phy_addr from no secure world, which store the mem info
 * buf_size: input, buffer size
 * return: 0 if exec success
 *     -1 if exec failed
 */
int hisi_sec_unmapfromsmmu(unsigned long long buf_phys, unsigned long long buf_size);

/*
 * func: map to sec-smmu, and set sec flag
 * buf_phys: input, buffer phy_addr from no secure world, which store the mem info
 * buf_size: input, buffer size
 * return: sec-smmu if exec success
 *     0 if exec failed
 */
struct sec_mmb *hisi_sec_maptosmmu_and_setflag(unsigned long long buf_phys, unsigned long long buf_size);
/*
 * func: clear sec flag and unmap from sec-smmu
 * buf_phys: input, buffer phy_addr from no secure world, which store the mem info
 * buf_size: input, buffer size
 * return: 0 if exec success
 *     -1 if exec failed
 */
int hisi_sec_unmapfromsmmu_and_clrflg(unsigned long long buf_phys, unsigned long long buf_size);

/*
 * func: alloc a mem(cma of system) and set sec flag
 * bufname: input, the name of mem
 * size: input, the size of mem with which it will be allocated
 * memtype: input, mem type,1 system(smmu), 0 cma
 * return:  phys_addr or sec-smmu if exec success
 *      0 if exec failed
 */
unsigned long long hisi_sec_alloc(const char *bufname, unsigned long long size, int memtype);

/*
 * func: free the mem and clear the sec flag
 * sec_addr: input, sec addr, sec-smmu or phys_addr
 * memtype: input, the address type, 1 sec_addr == sec_smmu, 0 sec_addr == phys_addr
 * return: 0 if exec success
 *     -1 if exec failed
 */
int hisi_sec_free(unsigned long long sec_addr, int memtype);

/*
 * func: map to sec cpu in user space
 * sec_addr: input, sec addr of sec mem
 * memtype: input, the address type, 1 sec_addr == sec_smmu, 0 sec_addr == phys_addr
 * cached: input, the cache attr when to map cpu, 1 map with cache, 0 map with no cache
 * return: sec cpu virt address if exec success
 *     NULL if exec failed
 */
unsigned int hisi_sec_map_to_cpu(unsigned long long sec_addr, int memtype, int cached);


/*
 * func: unmap from sec cpu in user space
 * sec_addr: input, sec addr of sec mem
 * return: 0 if exec success
 *     -1 if exec failed
 */
int hisi_sec_unmap_from_cpu(void *sec_virt);

/*
 * func: map to sec cpu in kernel space
 * sec_addr: input, sec addr of sec mem
 * memtype: input, the address type, 1 sec_addr == sec_smmu, 0 sec_addr == phys_addr
 * datalen: input, the user mem map len
 * cached: input, the cache attr when mapping cpu, 1 cached map, 0 no cache map
 * return: sec cpu virt address if exec success
 *     NULL if exec failed
 */
unsigned int hisi_sec_kmap_to_cpu(unsigned long long sec_addr, unsigned int datalen, int memtype, int cached);

/*
 * func: unmap from sec cpu in kernel space
 * sec_addr: input, sec addr of sec mem
 * return: 0 if exec success
 *     -1 if exec failed
 */
int hisi_sec_kunmap_from_cpu(void *sec_virt);

/*
 * func: map to sec smmu:(sec share mem(cma) or sec mmz)
 * phys_addr: input, phys addr of sec mem(cma or sec mmz)
 * size: input, the size of mem
 * share_mem: input, the address type, 1 phys_addr is sec share mem(cma), 0 phys_addr is sec-mmz
 * return: sec smmu if exec success
 *     0 if exec failed
 */
unsigned int hisi_sec_map_to_sec_smmu(unsigned long long phys_addr, unsigned long long size, int share_mem);

/*
 * func: unmap from sec smmu:(sec share mem(cma) or sec mmz)
 * sec_addr: input, sec smmu addr of sec mem(cma or sec mmz)
 * share_mem: input, the address type, 1 sec share mem(cma), 0  sec-mmz
 * return: 0 if exec success
 *     -1 if exec failed
 */
int hisi_sec_unmap_from_sec_smmu(unsigned long long sec_smmu, int share_mem);

/*
 * func: normal mem map to sec cpu in user space
 * nonsec_addr: input, normal mem addr (nosec smmu or phys)
 * memtype: input, the address type of nonsec_addr, 1 nosec smmu, 0  phys addr
 * cached: input, the cache attr when to map cpu, 1 map with cached, 0 map with no cached
 * return: sec cpu virt addr if exec success
 *     NULL if exec failed
 */
unsigned int hisi_nonsec_mem_map_to_sec_cpu(unsigned long long nonsec_addr, int memtype, int cached);

/*
 * func: normal mem unmap from sec cpu in user space
 * va_addr: input, sec cpu virt addr of mem
 * return: 0 if exec success
 *     -1 if exec failed
 */
int hisi_nosec_mem_unmap_from_sec_cpu(void *va_addr);

/*
 * func: normal mem map to sec cpu in kernel space
 * nonsec_addr: input, normal mem addr (nosec smmu or phys)
 * memtype: input, the address type of nonsec_addr, 1 nosec smmu, 0  phys addr
 * datalen: input, the user mem len
 * cached: input, the cache attr when to map, 1 mapped with cache, 0 mapped with no cache
 * return: sec cpu virt addr if exec success
 *     NULL if exec failed
 */
unsigned int hisi_nonsec_mem_kmap_to_sec_cpu(unsigned long long nonsec_addr, unsigned int datalen, int memtype,
                                             int cached);

/*
 * func: normal mem unmap from sec cpu in kernel space
 * va_addr: input, sec cpu virt addr of mem
 * return: 0 if exec success
 *     -1 if exec failed
 */
int hisi_nosec_mem_kunmap_from_sec_cpu(void *va_addr);

/*
 * func: normal mem map to sec smmu
 * nonsec_addr: input, normal mem addr (nosec smmu or phys)
 * memtype: input, the address type of nonsec_addr, 1 nosec smmu, 0  phys addr
 * return: sec smmu addr if exec success
 *     0 if exec failed
 */
unsigned int hisi_nosec_mem_map_to_sec_smmu(unsigned long long nonsec_addr, int memtype);

/*
 * func: normal mem unmap from sec smmu
 * sec_smmu: input, sec smmu of mem
 * return: 0 if exec success
 *     -1 if exec failed
 */
int hisi_nosec_mem_unmap_from_sec_smmu(unsigned long long sec_smmu);

/*
 * func: get smmu pgtbl base and dustbin base of smmu write/read
 * smmu_e_raddr: output, the dustbin base of smmu read
 * smmu_e_waddr: output, the dustbin base of smmu write
 * smmu_pgtbl: output, the smmu pgtbl base
 */
void get_sec_smmu_pgtblbase(unsigned long long *smmu_e_raddr,
                            unsigned long long *smmu_e_waddr,
                            unsigned long long *smmu_pgtbl);

/*
 * func: closed agent
 * when unregister agent from REE, TEE should give a message to agent in REE
 * to finish the thread.
 */
int agent_closed(void);

/*
 * func: a general system call
 * cma:input, means the command
 * arg0:input
 * arg1:input
 */
int sec_ioctl(unsigned long long cmd, unsigned long long arg0, unsigned long long arg1);

/*
 * func: flush mem via virt and size
 * virt: input, the virt addr of mem
 * size: input, the size of mem
 */
void hisi_mem_flush(void *virt, unsigned long long size);

/*
 * func: check if the addr is sec or not
 * addr: input, the addr need to check
 * iommu: input, the type of addr, 1 smmu , 0 phys
 * is_sec: output, the sec attr of addr, legal value only return success
 *
 */
int is_sec_mem(unsigned int addr, int iommu, bool *is_sec);

/*
 * func: smmu module init function
 */
int smmu_init(void);

/*
 * func: get phys addr via sec smmu addr
 * sec_smmu: input, the sec smmu addr
 * size: input, the size of mem
 * phys_addr: output, the phys addr of mem
 */
int get_phys_by_sec_smmu(unsigned long long sec_smmu, unsigned long long size, unsigned long long *phys_addr);
int hi_smmu_driver_ioctl(int swi_id, struct drv_param *params, uint64_t permissions);
int hisi_attach_smmu(unsigned long long secsmmu, unsigned long long size, unsigned int ssm_tag);

int get_sec_mem_info(unsigned long long handle_id, unsigned long long *secsmmu,
                     unsigned long long *phys_addr, unsigned long long *size);
int get_nssmmu_info(unsigned long long handle_id, unsigned long long *nssmmu);
int get_nsmmz_info(unsigned long long handle_id, unsigned long long *phys_addr);
int get_handle_id(unsigned long long secsmmu, unsigned long long *handle_id);

/*
 * func: init ddr(2G) last 256M mem non secure, avoid tzasc cpu write access fault
 */
void non_secure_mem_init(void);
#endif
