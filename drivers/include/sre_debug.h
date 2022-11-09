/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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
