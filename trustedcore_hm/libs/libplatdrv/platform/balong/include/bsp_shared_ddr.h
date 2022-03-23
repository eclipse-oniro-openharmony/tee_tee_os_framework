#ifndef __MODEM_SHARED_DDR__
#define __MODEM_SHARED_DDR__

#include <product_config.h>
#include <osl_balong.h>

#define SHM_BASE_ADDR           DDR_SHARED_MEM_ADDR
#define SHM_OFFSET_NV           (0)


#define SHM_SEC_BASE_ADDR               DDR_SEC_SHARED_ADDR
#define SHM_SEC_BASE_SIZE               DDR_SEC_SHARED_SIZE

#define SHM_OFFSET_PROTECT_BARRIER      (0x0)

#define SHM_OFFSET_PARAM_CFG            (SHM_OFFSET_PROTECT_BARRIER + SHM_SIZE_PROTECT_BARRIER)

#define SHM_OFFSET_SEC_ICC              (SHM_OFFSET_PARAM_CFG + SHM_SIZE_PARAM_CFG)

#define SHM_OFFSET_SEC_RESERVED         (SHM_OFFSET_SEC_ICC + SHM_SIZE_SEC_ICC)

#define SHM_OFFSET_SEC_MDMA9_PM_BOOT    (SHM_OFFSET_SEC_RESERVED + SHM_SIZE_SEC_RESERVED)

#define SHM_OFFSET_SEC_CERT             (SHM_OFFSET_SEC_MDMA9_PM_BOOT + SHM_SIZE_SEC_MDMA9_PM_BOOT)


#define PARAM_MAGIC_OFFSET              (0x0)
#define PARAM_CFG_OFFSET                (0x8)

#ifndef phy_addr_t
typedef unsigned long phy_addr_t;
#endif

/**
 * @brief π≤œÌƒ⁄¥Ê Ù–‘.
 */
typedef enum {
    SHM_UNSEC = 0x0,
    SHM_SEC,
    SHM_NSRO,
    SHM_ATTR_MAX
}mdrv_shm_attr_e;

void* bsp_mem_share_get(const char *name, phy_addr_t *addr, unsigned int *size, u32 flag);
#endif
