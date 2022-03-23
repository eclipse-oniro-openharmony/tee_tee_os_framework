/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#ifndef _EICC_PMSR_H
#define _EICC_PMSR_H
#include "eicc_platform.h"

int eicc_chn_suspend(void);
void eicc_chn_resume(void);
int eicc_dev_suspend(void);
void eicc_dev_resume(void);

u32 eicc_pmsr_dump_save(u8 *buf, u32 len);

#endif
