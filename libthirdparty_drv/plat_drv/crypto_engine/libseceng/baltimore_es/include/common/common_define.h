/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: universal data type
 * Author     : m00475438
 * Create     : 2019/08/25
 */
#ifndef __COMMON_DEFINE_H__
#define __COMMON_DEFINE_H__
#include <pal_types.h>
#include <pal_errno.h>

/**
 * @brief boolean type
 */
enum sec_bool_e {
	SEC_YES    =  (0x05),
	SEC_NO     =  (0x0A),

	SEC_TRUE    =  (0x5452A5A5),
	SEC_FALSE   =  (0x4641A5A5),
};

/**
 * @brief status type
 */
enum sec_status_e {
	SEC_ON      =  SEC_YES,
	SEC_OFF     =  SEC_NO,

	SEC_ENABLE  =  SEC_YES,
	SEC_DISABLE =  SEC_NO,

	SEC_LOCK    = SEC_YES,
	SEC_UNLOCK  = SEC_NO,

	SEC_MASK    = SEC_YES,
	SEC_UNMASK  = SEC_NO,
};

/**
 * @brief  basic data struct ,include data buf and data size
 */
struct basic_data {
	u8     *pdata; /* point to data buffer */
	u32    size;   /* buffer size */
};

#endif /* end of __COMMON_DEF_H__ */
