/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: declare fpga or not func
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2018/08/15
 */

#ifndef __PAL_CPU_PLAT_H__
#define __PAL_CPU_PLAT_H__

/*
 * @brief      : check if it is fpga or not
 * @param[in]  : NA
 * @return     : PAL_TRUE-fpga, PAL_FALSE-asic
 */
u32 pal_is_fpga(void);

#endif /*__PAL_CPU_PLAT_H__*/

