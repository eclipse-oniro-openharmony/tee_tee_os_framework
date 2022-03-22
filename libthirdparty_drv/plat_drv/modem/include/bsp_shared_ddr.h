#ifndef __MODEM_SHARED_DDR__
#define __MODEM_SHARED_DDR__

#include <product_config_drv.h>

#define SHM_BASE_ADDR           DDR_SHARED_MEM_ADDR
#define SHM_OFFSET_NV           (0)


#define SHM_SEC_BASE_ADDR               DDR_SEC_SHARED_ADDR

#define SHM_OFFSET_PROTECT_BARRIER      (0x0)

#define SHM_OFFSET_PARAM_CFG            (SHM_OFFSET_PROTECT_BARRIER + SHM_SIZE_PROTECT_BARRIER)

#define SHM_OFFSET_SEC_ICC              (SHM_OFFSET_PARAM_CFG + SHM_SIZE_PARAM_CFG)

#define SHM_OFFSET_SEC_RESERVED         (SHM_OFFSET_SEC_ICC + SHM_SIZE_SEC_ICC)

#define SHM_OFFSET_SEC_MDMA9_PM_BOOT    (SHM_OFFSET_SEC_RESERVED + SHM_SIZE_SEC_RESERVED)

#define SHM_OFFSET_SEC_CERT             (SHM_OFFSET_SEC_MDMA9_PM_BOOT + SHM_SIZE_SEC_MDMA9_PM_BOOT)


#define PARAM_MAGIC_OFFSET              (0x0)
#define PARAM_CFG_OFFSET                (0x8)

#endif
