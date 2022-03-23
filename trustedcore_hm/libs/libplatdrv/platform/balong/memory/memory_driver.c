#include "memory_driver.h"
#include <drv_mem.h>
#include <register_ops.h>
#include <drv_module.h>
#include <sre_sys.h>
#include <osl_balong.h>
#include <sre_typedef.h>
#include <securec.h>
#include "mem_ops.h"
#include <hisi_boot.h>
#include <hisi_debug.h>

#ifdef CONFIG_SHARED_MEMORY
mem_mgr_info_s g_bydts_mem_info[SHM_ATTR_MAX] = {};

#define MEM_INFO_GET_DTSINFO(x)       (g_bydts_mem_info[x].dts_info)
#define MEM_INFO_GET_ADDR(x)       (g_bydts_mem_info[x].base_addr)
#define MEM_INFO_GET_VIRT_ADDR(x)       (g_bydts_mem_info[x].virt_base_addr)
#define MEM_INFO_GET_SIZE(x)       (g_bydts_mem_info[x].size)
#define MEM_INFO_GET_DTSINFO_SIZE(x)       (g_bydts_mem_info[x].dts_info_size)
#define MEM_NODE_GET_NEXT(dts_info, i) (dts_info + i)

shm_layout_s g_shm_layout[SHM_ATTR_MAX] = {
    {DDR_SHARED_UNSEC_ADDR, DDR_SHARED_UNSEC_SIZE},
    {DDR_SHARED_SEC_ADDR, DDR_SHARED_SEC_SIZE},
    {DDR_SHARED_NSRO_ADDR, DDR_SHARED_NSRO_SIZE},
};

int mem_info_init(u32 mem_id)
{
    unsigned int virt_addr;
    unsigned int addr;
    unsigned int total_size;
    mem_mgr_node_info_s *shm_dtsinfo = NULL;

    if (mem_id >= SHM_ATTR_MAX) {
        mem_err("mem_id %d is overflow.\n", mem_id);
        return MEM_ERROR;
    }

    addr = g_shm_layout[mem_id].addr;
    total_size = g_shm_layout[mem_id].size;
    if (sre_mmap(addr, total_size, &virt_addr, secure, non_cache)) {
        mem_err("map data buffer addr=0x%llx size=0x%x error\n", addr, total_size);
        return MEM_ERROR;
    }

    MEM_INFO_GET_VIRT_ADDR(mem_id) = (void *)(uintptr_t)((uintptr_t)virt_addr + SHM_DTSINFO_SIZE);
    MEM_INFO_GET_ADDR(mem_id) = (phy_addr_t)(SHM_DTSINFO_SIZE + (unsigned int)addr);
    MEM_INFO_GET_SIZE(mem_id) = (unsigned int)((unsigned int)total_size - SHM_DTSINFO_SIZE);
    MEM_INFO_GET_DTSINFO_SIZE(mem_id) = SHM_DTSINFO_SIZE;
    shm_dtsinfo = (mem_mgr_node_info_s *)(uintptr_t)virt_addr;
    MEM_INFO_GET_DTSINFO(mem_id) = shm_dtsinfo;

    return MEM_OK;
}

void* bsp_mem_share_get(const char *name, phy_addr_t *addr, unsigned int *size, u32 flag)
{
    u32 meminfo_id;
    mem_mgr_node_info_s *dts_info = NULL;
    u32 i;
    u32 max_num;
    if (name == NULL) {
        mem_err("[memory]name error!\n");
        return NULL;
    }
    if (size == NULL || addr == NULL) {
        mem_err("[memory]size or addr error!\n");
        return NULL;
    }
    if (flag >= SHM_ATTR_MAX) {
        mem_err("[memory]flag error!\n");
        return NULL;
    }
    meminfo_id = flag;
    dts_info = MEM_INFO_GET_DTSINFO(meminfo_id);
    if (dts_info == NULL) {
        mem_err("mem_dts %d info is NULL\n", flag);
        return NULL;
    }
    max_num = MEM_INFO_GET_DTSINFO_SIZE(flag) / sizeof(mem_mgr_node_info_s);
    for (i = 0; i < max_num; i++) {
        if (strcmp((MEM_NODE_GET_NEXT(dts_info, i))->name, name) == 0) {
            *size = (MEM_NODE_GET_NEXT(dts_info, i))->size;
            *addr = (phy_addr_t)(MEM_INFO_GET_ADDR(meminfo_id) + (MEM_NODE_GET_NEXT(dts_info, i))->offset);
            return (void *)((uintptr_t)MEM_INFO_GET_VIRT_ADDR(meminfo_id) + (MEM_NODE_GET_NEXT(dts_info, i))->offset);
        }
    }
    mem_err("[memory]mem %s not find in dts\n", name);
    return NULL;
}

int bsp_memory_init(void)
{
    if (memset_s((void*)g_bydts_mem_info, sizeof(g_bydts_mem_info), 0x0, (sizeof(mem_mgr_info_s) * SHM_ATTR_MAX))) {
        mem_err("[memory]memset_s error\n");
    }
    if (mem_info_init(SHM_SEC) != MEM_OK) {
        mem_err("[memory]shared_sec_mem init failed\n");
        return MEM_ERROR;
    }
    if (mem_info_init(SHM_NSRO) != MEM_OK) {
        mem_err("[memory]shared_sec_mem init failed\n");
        return MEM_ERROR;
    }
    if (mem_info_init(SHM_UNSEC) != MEM_OK) {
        mem_err("[memory]shared_unsec_mem init failed\n");
        return MEM_ERROR;
    }
    mem_err("[memory]init ok\n");
    return MEM_OK;
}

#else
unsigned int g_virt_base_addr;
struct share_mem_ctrl g_share_mem_mgr_ctrl[] = {
    {"seshm_barrier", SHM_OFFSET_PROTECT_BARRIER, SHM_SIZE_PROTECT_BARRIER},
    {"seshm_param_cfg", SHM_OFFSET_PARAM_CFG, SHM_SIZE_PARAM_CFG},
    {"seshm_icc", SHM_OFFSET_SEC_ICC, SHM_SIZE_SEC_ICC},
    {"seshm_reserved", SHM_OFFSET_SEC_RESERVED, SHM_SIZE_SEC_RESERVED},
    {"seshm_mdma9", SHM_OFFSET_SEC_MDMA9_PM_BOOT, SHM_SIZE_SEC_MDMA9_PM_BOOT},
    {"seshm_cert", SHM_OFFSET_SEC_CERT, SHM_SIZE_SEC_CERT},
};

void *bsp_mem_share_get(const char *name, phy_addr_t *addr, u32 *size, u32 flag)
{
    u32 i;
    (void)flag;
    if (name == NULL) {
        mem_err("name error!\n");
        return NULL;
    }
    if (size == NULL || addr == NULL) {
        mem_err("size or addr error!\n");
        return NULL;
    }
    for (i = 0; i < sizeof(g_share_mem_mgr_ctrl) / sizeof(g_share_mem_mgr_ctrl[0]); i++) {
        if (strcmp(g_share_mem_mgr_ctrl[i].name, name) == 0) {
            *size = g_share_mem_mgr_ctrl[i].size;
            *addr = SHM_SEC_BASE_ADDR + g_share_mem_mgr_ctrl[i].base_addr;
            return (void *)(uintptr_t)(g_virt_base_addr + g_share_mem_mgr_ctrl[i].base_addr);
        }
    }
    mem_err("%s mem_dtsinfo get failed\n", name);
    return NULL;
}

int bsp_memory_init(void)
{
    unsigned int addr = SHM_SEC_BASE_ADDR;
    unsigned int total_size = SHM_SEC_BASE_SIZE;
    if (sre_mmap(addr, total_size, &g_virt_base_addr, secure, non_cache)) {
        mem_err("map data buffer addr=0x%llx size=0x%x error\n", addr, total_size);
        return MEM_ERROR;
    }
    mem_err("[memory]init ok\n");
    return MEM_OK;
}
#endif

/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(memory_driver, 0, 0, 0, 0, bsp_memory_init, NULL, NULL, NULL, NULL);
/*lint -e528 +esym(528,*)*/
