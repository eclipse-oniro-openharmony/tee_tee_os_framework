/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Interface of eSE transmit data.
 * Create: 2019/7/30
 */

#ifndef __ESE_DATA_HANDLE_H__
#define __ESE_DATA_HANDLE_H__

#include "pthread.h"

#define ESE_TRS_OKAY                    0x00
#define ESE_TRS_PARAM_ERR               0x01
#define ESE_TRS_DATA_ERR                0x02
#define ESE_TRS_NON_EXIST               0x09

/*
 * data: pointer to data which is used to activate or disactivate
 * data_size: the length from the start to end of the pointer
 */
int ese_transmit_data(unsigned char *data, unsigned int data_size);

/*
 * data: pointer of data to read to
 * data_size: the data pointer length
 */
int ese_read_data(unsigned char *data, unsigned int data_size);
#endif
