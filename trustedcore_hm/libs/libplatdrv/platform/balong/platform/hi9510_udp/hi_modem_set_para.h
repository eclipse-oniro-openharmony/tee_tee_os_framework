/*
 * Copyright (C), 2013~2020, Hisilicon Technologies Co., Ltd. All rights reserved.
 */
#ifndef _HI_MODEM_SET_PARA_H_
#define _HI_MODEM_SET_PARA_H_

/* 修改SYSBOOT_PARA_OFFSET需要同步修改以下文件:
    vendor/hisi/modem/drv/ccore/include/fusion/bsp_sysboot.h
    vendor/hisi/modem/drv/acore/kernel/drivers/hisi/modem/drv/sysboot/sysboot_para.c
*/

#define SYSBOOT_PARA_OFFSET 0x100
#define MODEM_MEM_LAYOUT_ADDR_OFFSET (SYSBOOT_PARA_OFFSET)
#define MODEM_MEM_LAYOUT_SIZE_OFFSET (SYSBOOT_PARA_OFFSET + 0x4)
#define MODEM_IMAGE_OFFSET_FOR_4G    (SYSBOOT_PARA_OFFSET + 0x8)
#define MODEM_STACK_GUARD_OFFSET_FOR_4G (SYSBOOT_PARA_OFFSET + 0xC)
#define MODEM_MEM_PT_OFFSET_FOR_4G   (SYSBOOT_PARA_OFFSET + 0x10)

#endif
