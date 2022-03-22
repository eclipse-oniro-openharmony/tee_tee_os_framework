/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rtc timer pmic_wrap related functions defined in this file.
 * Author: zhangdeyao zhangdeyao@huawei.com
 * Create: 2020-11-23
 */
#ifndef DRV_TIMER_PLATFORM_RTC_PMIC_READ_H
#define DRV_TIMER_PLATFORM_RTC_PMIC_READ_H

#include <stdint.h>

/* macro for regsister@PMIC */
#define PMIF_ACC            (PMIF_SPI_BASE + 0xC00)
#define PMIF_WDATA_31_0     (PMIF_SPI_BASE + 0xC04)
#define PMIF_RDATA_31_0     (PMIF_SPI_BASE + 0xC14)
#define PMIC_WRAP_WACS2_CMD (PMIF_SPI_BASE + 0xC00 + 0x10 * PMIC_SWINF_NO)
#define PMIF_VLD_CLR        (PMIF_SPI_BASE + 0xC04 + 0x10 * PMIC_SWINF_NO)
#define PMIF_STA            (PMIF_SPI_BASE + 0xC08 + 0x10 * PMIC_SWINF_NO)
#define PMIF_READ           0x40

#define INT_MAX_VALUE 0xffff

/* external API */
int32_t pwrap_read(uint32_t adr, uint32_t *rdata);

#endif
