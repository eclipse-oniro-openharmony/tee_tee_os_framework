/****************************************************************************//**
 * @file   hat_framework.h
 * @brief
 * @par    Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   2018/08/20
 * @author L00265041
 * @note
 *
********************************************************************************/
#ifndef __HAT_FRAMEWORK_H__
#define __HAT_FRAMEWORK_H__
#include <pal_log.h>


/*===============================================================================
 *                               types/macros                                  *
===============================================================================*/
#define HAT_LOG_PREFIX "<autotest> "
#define HAT_INFO(fmt, ...)       PAL_INFO(HAT_LOG_PREFIX""fmt, ##__VA_ARGS__)
#define HAT_ERROR(fmt, ...)      PAL_ERROR(HAT_LOG_PREFIX""fmt, ##__VA_ARGS__)

#define FUNTION_NAME_LEN  8

typedef struct ntlv_struct_type_stru{
	u16 type;
	u16 opts;
} ntlv_struct_type_s;

typedef struct {
	char tag_name[FUNTION_NAME_LEN];
	ntlv_struct_type_s tag_type_s;
	u32 tag_length;
	u32 tag_value[0];
} se_ntlv_struct;


/*===========================================================================
 *                      functions                                          *
===========================================================================*/
s32 autotest_framework_case(u8 *data, u32 size, u32 *cost_time);
u32 hat_get_func_addr(const s8 *name, u32 len);
void hat_ion_pool_init(u32 ion_iova, u32 ion_va, u32 size);
void hat_cma_pool_init(uintptr_t cma_va, u32 cma_pa, u32 size);

#endif /* __HAT_FRAMEWORK_H__ */
