/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, hwi driver call function
 * Create: 2019-11-20
 */
#ifndef HWI_DRV_CALL_H
#define HWI_DRV_CALL_H
#include <stdint.h>

uint32_t tee_hwi_msg_register(uint32_t uw_hwi_num);
uint32_t tee_hwi_msg_deregister(uint32_t uw_hwi_num);
#endif /* HWI_DRV_CALL_H */
