#ifndef __BUS_DRV_TEST_TASK_H__
#define __BUS_DRV_TEST_TASK_H__

#include "stdint.h"

#ifdef DEF_ENG
uint32_t __tee_call_bus_drivers(uint32_t cmd,
     const char *parm_info, uint32_t parm_size);
#endif
#endif
