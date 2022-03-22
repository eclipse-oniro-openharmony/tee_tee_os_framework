/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * File Name: hi_tee_demo.h
 * Description: api demo
 * Author: Hisilicon
 * Created: 2019-07-08
 */

#ifndef _HI_TEE_DEMO_H
#define _HI_TEE_DEMO_H

#ifdef __cplusplus
extern "C"
{
#endif

int hi_tee_demo_hello(int data, void *addr);
int hi_tee_demo_ioctl(int data, void *addr, unsigned int size);
int hi_tee_demo_test(unsigned int cmd, void *addr, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* _HI_TEE_DEMO_H */

