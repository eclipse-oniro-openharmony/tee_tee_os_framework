#ifndef __HISI_HIEPS_TASK_H__
#define __HISI_HIEPS_TASK_H__

#include "stdint.h"

uint32_t __tee_call_hieps_drivers(uint32_t cmd, const char *input, uint32_t max_input_len,
                                  const char *parm_info, uint32_t parm_size);

#endif
