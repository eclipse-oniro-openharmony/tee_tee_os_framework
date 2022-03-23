/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: PKE data structure
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2019/07/22
 */
#ifndef __COMMON_PKE_H__
#define __COMMON_PKE_H__
#include <common_define.h>

#define PKE_NO_ENHANCED      0

/**
 * @brief basic point(x,y) structuress
 */
struct point {
	u8 *px;         /* point to x buffer */
	u8 *py;         /* point to y buffer */
	u32 size;       /* buffer size ,x and y size is same */
};

struct point_aff_cord {
	struct bn_data *px;
	struct bn_data *py;
};

#endif

