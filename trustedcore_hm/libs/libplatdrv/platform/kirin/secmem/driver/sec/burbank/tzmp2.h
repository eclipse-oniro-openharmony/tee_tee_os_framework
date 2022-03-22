/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mpu protect function head file
 * Author: bujing
 * Create: 2020-08-01
 */

#ifndef __TZMP2_H__
#define __TZMP2_H__

#define PRINT_INFO                           tlogi
#define MPU_ADDR_ZONE_4G                     0
#define MPU_ADDR_ZONE_8G                     1
#define MPU_ADDR_ZONE_16G                    2
#define MPU_ADDR_ZONE_32G                    3
#define ADDR_SHIFT_MODE_MASK                 3
#define ADDR_SHIFT_MODE_1                    1
#define ADDR_SHIFT_MODE_2                    2
#define DDR_SIZE_64K                         0x10000
#define DDR_SIZE_128K                        0x20000
#define DDR_SIZE_256K                        0x40000
#define DDR_SIZE_512K                        0x80000
#define DDR_SIZE_3G512M                      0xE0000000ULL
#define DDR_SIZE_4G                          0x100000000ULL
#define DDR_SIZE_8G                          0x200000000ULL
#define DDR_SIZE_8G512M                      0x220000000ULL
#define DDR_SIZE_16G                         0x400000000ULL
#define DDR_SIZE_16G512M                     0x420000000ULL
#define DDR_SIZE_32G                         0x800000000ULL
#define DDR_SIZE_32G512M                     0x820000000ULL
#define ADDR_SHIFT_MODE_1_START_ADDR         DDR_SIZE_16G
#define ADDR_SHIFT_MODE_1_END_ADDR           DDR_SIZE_16G512M
#define ADDR_SHIFT_MODE_2_START_ADDR         DDR_SIZE_32G
#define ADDR_SHIFT_MODE_2_END_ADDR           DDR_SIZE_32G512M
#define CA_RD_ENABLE                         0xA
#define CA_WR_ENABLE                         0xA
#define CA_RD_DISABLE                        0x5
#define CA_WR_DISABLE                        0x5
#define DDR_CA_CFG_CHECK_CNT                 1000
#define OK                                   0
#define ERROR                                (-1)
#define get_mpu_addr_zone(val)               ((val & 0x30) >> 4)

enum mpu_cfg_type {
	MPU_SET_SEC,
	MPU_UNSET_SEC,
	MPU_CHECK_SEC,
};

#endif
