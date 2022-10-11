/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, debug print function
 * Create: 2019-11-08
 */
#ifndef DRIVERS_SRE_DEBUG_H
#define DRIVERS_SRE_DEBUG_H

/* this switch config rtosck and framework can printf debug and erro info */
#ifdef DEBUG_SWITCH
#define uart_printf uart_printf_func
#else
#define uart_printf(fmt, ...)
#endif
#endif /* DRIVERS_SRE_DEBUG_H */
