/**
 * @file   : common_def.h
 * @brief  : universal data type
 * @par    : Copyright(c) 2018-2034, HUAWEI Technology Co., Ltd.
 * @date   : 2018/01/20
 * @author : m00172947
 */
#ifndef __COMMON_DEF_H__
#define __COMMON_DEF_H__
#include <pal_types.h>
#include <pal_errno.h>

typedef err_bsp_t (*sec_callback_f) (u8 *arg);

/**
 * @brief boolean type
 */
typedef enum sec_state_enum {
	SEC_YES    =  (0x05),
	SEC_NO     =  (0x0A),

	SEC_TRUE    =  (0x5452A5A5),
	SEC_FALSE   =  (0x4641A5A5),
} sec_bool_e;

/**
 * @brief status type
 */
typedef enum sec_status_enum {
	SEC_ON      =  SEC_YES,
	SEC_OFF     =  SEC_NO,

	SEC_ENABLE  =  SEC_YES,
	SEC_DISABLE =  SEC_NO,

	SEC_LOCK    = SEC_YES,
	SEC_UNLOCK  = SEC_NO,

	SEC_MASK    = SEC_YES,
	SEC_UNMASK  = SEC_NO,
} sec_status_e;

#endif /* end of __COMMON_DEF_H__ */
