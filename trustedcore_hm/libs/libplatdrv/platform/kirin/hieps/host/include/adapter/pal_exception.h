/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: define exception
 * Author     : l00370476, liuchong13@huawei.com
 * Create     : 2018/08/13
 */

#ifndef __PAL_EXCEPTION_H__
#define __PAL_EXCEPTION_H__
#include <pal_types.h>

/*
 * @param[in]  : module module id, refer to ::bsp_module_e
 * @param[in]  : errno error coding, refer to ::ERR_MAKEUP
 */
void pal_exception_process(u32 module, err_bsp_t errno);

#endif /*__PAL_EXCEPTION_H__*/

