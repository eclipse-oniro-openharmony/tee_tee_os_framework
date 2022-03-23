#include "memory_layout.h"
#include <sre_sys.h>
#include <sre_typedef.h>
#include <osl_balong.h>
#include <securec.h>
#include <drv_module.h>
#include <hisi_boot.h>
#include <hisi_debug.h>
#include <product_config.h>
#include <bsp_shared_ddr.h>

#ifdef CONFIG_MEMORY_LAYOUT
mem_layout g_mem_layout_info;
#else
mem_node_info g_mem_layout_info[] = {
#ifdef DDR_SEC_SHARED_ADDR
    {DDR_SEC_SHARED_ADDR, DDR_SEC_SHARED_SIZE, "sec_share_ddr"},  
#endif
#ifdef DDR_MCORE_ADDR
    {DDR_MCORE_ADDR, DDR_MCORE_SIZE, "mdm_ddr"},
#endif
};
#endif

unsigned long mdrv_mem_region_get(const char *name, unsigned int *size)
{
    mem_node_info *mem_info = NULL;
    unsigned int max_rec;
    unsigned long phy_addr;
    unsigned int i;

    if (name == NULL || size == NULL) {
        mem_err("[memory_layout]input error!\n");
        return 0;
    }

#ifdef CONFIG_MEMORY_LAYOUT
    mem_info = g_mem_layout_info.memory_info;
    max_rec = g_mem_layout_info.size / sizeof(mem_node_info);
#else
    mem_info = g_mem_layout_info;
    max_rec = sizeof(g_mem_layout_info) / sizeof(mem_node_info);
#endif
    for (i = 0; i < max_rec; i++) {
        if (strcmp((mem_info + i)->name, name) == 0) {
            phy_addr = (unsigned long)((mem_info + i)->addr);
            *size = (mem_info + i)->size;
            return phy_addr;
        }
    }
    *size = 0;
    mem_err("[memory_layout]get memory %s error!\n", name);
    return 0;
}

int bsp_memory_layout_init(void)
{
#ifdef CONFIG_MEMORY_LAYOUT
    unsigned long addr;
    void *virt_addr = NULL;

    mem_err("[memory_layout]init start\n");
    virt_addr = bsp_mem_share_get("nsroshm_memory_layout", &addr, &g_mem_layout_info.size, SHM_NSRO);
    if (virt_addr == NULL) {
        mem_err("[memory_layout]bsp_mem_share_get error\n");
        return MEM_ERROR;
    }
    g_mem_layout_info.memory_info = (mem_node_info *)(uintptr_t)virt_addr;
    mem_err("[memory_layout]init ok\n");
#endif
    return MEM_OK;
}

/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(memory_layout_driver, 0, 0, 0, 0, bsp_memory_layout_init, NULL, NULL, NULL, NULL);
/*lint -e528 +esym(528,*)*/

