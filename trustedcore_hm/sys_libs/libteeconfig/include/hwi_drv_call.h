/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, hwi driver call function
 * Create: 2019-11-20
 */
#ifndef HWI_DRV_CALL_H
#define HWI_DRV_CALL_H
#include "sre_typedef.h"

UINT32 __SRE_HwiMsgRegister(HWI_HANDLE_T uwHwiNum);
UINT32 __SRE_HwiMsgDeregister(HWI_HANDLE_T uwHwiNum);
#endif /* HWI_DRV_CALL_H */
