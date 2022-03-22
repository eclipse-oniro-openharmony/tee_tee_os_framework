/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: This file define some macro and api for load sec bin file
 * Author: chenweiyu 00416071
 * Create: 2019-05-24
 */

#ifndef _HIVP_H_
#define _HIVP_H_

#define SIZE_1M                   0x100000
#define IVP_IMAGE_SECTION_MAX_NUM 6
#define IVP_IMAGE_DDR_SECTION_NUM 3
#define IVP_IMAGE_DDR_ADDRESS     0xE0000000

struct img_sec_info {
    unsigned short index;
    unsigned char type;
    unsigned char attribute;
    unsigned int offset;
    unsigned int vaddr;
    unsigned int size;
};

#endif /* _HIVP_H_ */
