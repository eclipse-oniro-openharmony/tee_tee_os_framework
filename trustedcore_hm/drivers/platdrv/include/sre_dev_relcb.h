/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: declare dev relcb related functions
 * Create: 2019-11-20
 */
#ifndef PLATDRV_SRE_DEV_RELCB_H
#define PLATDRV_SRE_DEV_RELCB_H
#include <stdint.h>

/* keep these definations for compatible thirdparty driver */
typedef int32_t (*DEV_RELEASE_CALLBACK) (void *data);
uint32_t SRE_TaskRegister_DevRelCb(DEV_RELEASE_CALLBACK dev_relcb, void *data);
void SRE_TaskUnRegister_DevRelCb(DEV_RELEASE_CALLBACK dev_relcb, const void *data);

typedef int32_t (*dev_release_callback) (void *data);
uint32_t task_register_devrelcb(dev_release_callback dev_relcb, void *data);
void task_unregister_devrelcb(dev_release_callback dev_rel_cb, const void *data);

#endif /* PLATDRV_SRE_DEV_RELCB_H */
