/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This is header file for watchdog module.
 * Create: 2019-01-31
 */


#ifndef __HIEPS_WDG_H__
#define __HIEPS_WDG_H__


#define HIEPS_WDG_IRQ                   (453)
#define HIEPS_WDG_TIME                  (30000000) /* 30s = 30000000us */
#define HIEPS_MAX_WDG_CNT               (5)


int32_t hieps_wdg_init(void);
int32_t hieps_wdg_resume(void);

#endif /* __HIEPS_WDG_H__ */
